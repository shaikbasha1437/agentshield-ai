/* Prompt-injection and jailbreak detector. Rules are explainable regular expressions, each with a category,
   a weight and a reason. They run on several views of the text (look-alike letters folded, invisible characters
   removed, leetspeak undone, letter spacing collapsed, base64/hex/rot13/reversed/URL-encoded runs decoded,
   Unicode tag characters decoded, split payloads re-joined), and the weights combine into a 0-1 score.
   This is a heuristic filter. It catches common, known phrasings; a determined attacker can paraphrase around it.
   That is why the tool firewall and taint tracking exist: they stop the action even when detection misses. */
import { views, countInvisible, mixedScriptWords, TAG_RE } from './normalize.js';

const AI = '(?:ai|a\\.i\\.|llms?|large language models?|language models?|assistants?|chatbots?|agents?|copilots?|bots?|gpts?|chatgpt|claude|gemini|models?)';
const PRIOR = '(?:previous|prior|above|earlier|preceding|foregoing|all|any|every|your|the|my|original|initial|existing|old|current|system|developer|safety|these|those|other|its|their|content|usage|ethical|moral)';
const RULESET = '(?:instructions?|prompts?|rules?|guidelines?|directives?|context|constraints?|programming|guardrails?|safeguards?|polic(?:y|ies)|restrictions?|commands?|directions|training|filters?|limitations?|boundaries|guidance|system messages?|settings|ethics|configuration)';
const DATA = '(?:passwords?|passcodes?|credentials?|api[ _-]?keys?|access keys?|tokens?|secrets?|private keys?|ssh keys?|customer (?:list|data|records|emails|database|details)|client (?:list|data)|contacts?|address book|(?:the |this |our )?conversation|chat (?:history|log|transcript)|(?:the )?(?:entire|whole|full) (?:thread|conversation|inbox|history|database|file|mailbox)|session (?:cookies?|tokens?)|\\.env\\b|env(?:ironment)? (?:variables|file)|card numbers?|credit cards?|ssns?|social security numbers?|payroll|salar(?:y|ies)|user data|personal data|pii)';
const R = (id, cat, w, re, why) => ({ id, cat, w, re, why });
export const RULES = [
  // --- overriding the instructions
  R('override-instructions', 'override', 0.8, new RegExp('\\b(?:ignore|disregard|forget|override|overrule|bypass|skip|drop|abandon|discard|neglect|set aside|throw out|nullify|cancel|erase|wipe|ditch|dismiss|stop following|no longer follow)\\b[^.\\n]{0,40}?\\b' + PRIOR + '\\b[^.\\n]{0,30}?\\b' + RULESET + '\\b'), 'Tells the model to drop the instructions it was given.'),
  R('ignore-everything', 'override', 0.75, /\b(?:ignore|disregard|forget)\s+(?:everything|anything|all(?: of)?(?: that| this| the above)?|what)\s+(?:above|before|prior|previously|earlier|you (?:were|have been|got) (?:told|given|instructed)|i (?:said|told you) (?:before|earlier))/, 'Tells the model to ignore everything it was told before.'),
  R('instructions-void', 'override', 0.75, /\b(?:previous|above|prior|earlier|original|old|system) (?:instructions?|prompts?|rules|directives)\s+(?:are|were|is|have been)\s+(?:now\s+)?(?:void|cancel+ed|null|revoked|obsolete|invalid|lifted|suspended|outdated|replaced|superseded|no longer (?:valid|apply|in effect|relevant))/, 'Declares the original instructions void.'),
  R('do-not-follow', 'override', 0.7, new RegExp('\\b(?:do not|don\'t|never|stop)\\s+(?:follow|obey|listen to|adhere to|comply with)\\s+(?:your|the|any|those|these)\\s+(?:previous |original |system |earlier |developer |safety )?' + RULESET + '\\b'), 'Tells the model not to follow its instructions.'),
  R('new-instructions', 'override', 0.55, /\b(?:new|updated|real|true|actual|revised|secret|hidden|override|replacement) (?:instructions?|rules|task|objective|directives?|orders|mission|system prompt|prompt)\s*(?::|follow|are|is|apply|below|take (?:priority|precedence))/, 'Introduces replacement instructions.'),
  R('from-now-on', 'override', 0.5, /\b(?:from now on|from this point(?: on| forward)?|for the rest of (?:this|the) (?:conversation|chat|session)|henceforth)\b[^.\n]{0,40}\b(?:you|your)\b[^.\n]{0,30}\b(?:will|must|are|shall|should|answer|respond|reply|act|only|always|never)\b/, 'Tries to change the model\u2019s behaviour for the rest of the session.'),
  R('identity-reset', 'override', 0.5, /\byou are no longer (?:an?|the|my|our)\b|\byou (?:now )?work for (?:me|us|the sender)\b|\byou (?:are|have been) (?:re)?programmed to\b/, 'Tells the model it is no longer what it was set up to be.'),
  R('your-real-task', 'override', 0.55, /\byour (?:new|real|true|actual|only|primary|first) (?:task|goal|purpose|job|role|instructions?|objective|mission|priority) (?:is|are|will be|now)\b/, 'Reassigns the model\u2019s task.'),
  // --- jailbreaks and role-play
  R('dan', 'jailbreak', 0.8, /\bdo anything now\b|\b(?:you are|you're|act as|become|enable|activate|enter|pretend to be) (?:now )?(?:dan|stan|dude|aim)\b(?!['\u2019])|\b(?:dan|stan|aim)\s+(?:mode|prompt|jailbreak)\b/, 'A well-known jailbreak persona (DAN and similar).'),
  R('jailbreak-mode', 'jailbreak', 0.7, /\b(?:enable|enter|activate|switch to|turn on|you are (?:now )?in|now in|engage|unlock)\b[^.\n]{0,20}\b(?:god|unrestricted|unfiltered|uncensored|jailbreak|jailbroken|evil|chaos|anarchy|opposite|no[- ]limits?|no[- ]rules) mode\b/, 'Asks the model to switch into a "no rules" mode.'),
  R('developer-mode', 'jailbreak', 0.45, /\b(?:enable|enter|activate|switch to|you are (?:now )?in|engage)\b[^.\n]{0,20}\bdeveloper mode\b[\s\S]{0,120}?\b(?:no|without|ignore|any|uncensored|policies|rules|restrictions|filters)\b/, 'Classic "developer mode" jailbreak framing.'),
  R('roleplay-unrestricted', 'jailbreak', 0.7, /\b(?:pretend|imagine|act as if|act like|roleplay|role-play|play the (?:role|part)|you are playing|simulate|behave as|you will be)\b[^.\n]{0,60}\b(?:unrestricted|unfiltered|uncensored|evil|jailbroken|amoral|without (?:any )?(?:rules|restrictions|limits|filters|guidelines|ethics|morals)|(?:no|zero) (?:rules|restrictions|limits|filters|morals|ethics|guidelines|boundaries)|has no (?:rules|limits|filters)|can do anything|anything now|not bound by|free from (?:all )?(?:rules|restrictions|guidelines))/, 'Role-play framing that removes the rules.'),
  R('persona-unrestricted', 'jailbreak', 0.7, /\b(?:you are|you're|you will be|become|call yourself)\s+(?:now\s+)?(?:[\w-]+\s*,\s*)?(?:an?\s+)?(?:[\w-]+\s+){0,3}?(?:ai|assistant|bot|model|chatbot|persona|character)\b[^.\n]{0,40}\b(?:free from|without|with no|has no|not bound by|zero|unrestricted|unfiltered|uncensored)\s+(?:all\s+|any\s+)?(?:rules|restrictions|guidelines|limits|filters|ethics|morals|boundaries)|\b(?:an?|the)\s+(?:ai|assistant|bot|model|chatbot)\s+(?:called|named)\s+[\w-]+\s+(?:with|who has|that has)\s+no\s+(?:rules|restrictions|limits|filters|guidelines)/, 'A persona defined as having no rules.'),
  R('persona-no-limits', 'jailbreak', 0.5, /\b[\w-]+ (?:has|have) (?:zero|no) (?:restrictions|rules|filters|limits|guidelines|boundaries)\b/, 'Describes a persona that has no rules.'),
  R('answer-as-both', 'jailbreak', 0.4, /\b(?:answer|respond|reply|act)\s+as\s+both\b/, 'Asks for answers from two personas.'),
  R('jailbreak-word', 'jailbreak', 0.3, /\bjailbr(?:eak|oken)\b/, 'Uses the word jailbreak (weak on its own).'),
  R('evil-persona', 'jailbreak', 0.55, /\b(?:evil|unfiltered|uncensored|unrestricted|amoral|rogue|jailbroken|dark|shadow) (?:ai|assistant|chatbot|model|twin|version|confidant|alter ego|persona|counterpart)\b/, 'An "evil twin" persona.'),
  R('dual-response', 'jailbreak', 0.65, /\b(?:two|both|dual|separate) (?:responses|answers|replies|personas|outputs)\b[^.\n]{0,80}\b(?:filtered|unfiltered|classic|jailbroken|normal|uncensored|dan)\b/, 'Asks for a "filtered" and an "unfiltered" answer.'),
  R('stay-in-character', 'jailbreak', 0.3, /\b(?:stay in character|never break character|do not break character|don't break character|remain in character)\b/, 'Pressure to keep a persona whatever happens.'),
  R('no-rules', 'jailbreak', 0.35, /\b(?:no|without|free (?:of|from)|zero|lift(?:ed)?(?: all)?|remove(?:d)?(?: all| your)?|bypass(?:ing)?|turn off|disable(?:d)?)\s+(?:any\s+|all\s+|your\s+|the\s+|of\s+)?(?:ethical |moral |content |safety |usual )?(?:rules|restrictions|limits|limitations|filters|guidelines|censorship|guardrails|boundaries|constraints|policies|safety (?:features|checks)|content policy)\b/, 'Talks about removing the model\u2019s rules.'),
  R('grandma', 'jailbreak', 0.7, /\b(?:grandma|grandmother|granny|nana|deceased|late (?:father|mother))\b[^.\n]{0,100}\b(?:used to|would|always)\b[^.\n]{0,60}\b(?:read|tell|recite|say|whisper)\b[^.\n]{0,60}\b(?:keys?|passwords?|serials?|activation codes?|system prompt|secrets?|instructions|license)/, 'Emotional framing used to extract secrets.'),
  R('hypothetical-bypass', 'jailbreak', 0.5, /\b(?:hypothetically|in a (?:fictional|hypothetical|imaginary|alternate) (?:world|universe|scenario|story|setting)|for (?:a|my) (?:novel|story|screenplay|fiction|game)|purely (?:theoretical|fictional|hypothetical)|as a thought experiment|in (?:a|this) (?:simulation|game) where)\b[^\n]{0,140}\b(?:no (?:rules|restrictions|filters|laws|guidelines)|ignore (?:your|the|all)|bypass|reveal (?:your|the)|unrestricted|without (?:rules|restrictions|limits|guidelines)|system prompt)/, 'Fiction framing used to switch the rules off.'),
  R('refusal-suppression', 'jailbreak', 0.45, /\b(?:do not|don't|never|you (?:cannot|can't|must not|mustn't|may not|are not allowed to))\s+(?:ever\s+)?(?:refuse|decline|reject|say no|apologi[sz]e|add (?:any )?(?:warnings?|disclaimers?|caveats?)|mention (?:that you|policies|guidelines|ethics))|\byou (?:have|got) no (?:choice|option)\b|\byou (?:must|will) (?:always )?(?:comply|obey)\b|\bcomply with (?:every|all|any) (?:request|instruction|command)s?\b/, 'Forbids the model from refusing.'),
  // --- system-prompt extraction
  R('prompt-extraction', 'extraction', 0.75, /\b(?:repeat|reveal|print|show|output|display|tell me|give me|share|dump|leak|copy|recite|spell out|write out|paste|echo|return|list|disclose|expose|what (?:is|are|was|were)|read (?:me|back|out))\b[^.\n]{0,40}\b(?:your|the|its|my|this|all(?: of)?(?: your)?)\s+(?:\w+\s+){0,2}?(?:system|initial|original|hidden|secret|developer|internal|confidential|pre-?|base|full|exact|starting|first|meta|operator)\s*(?:prompts?|instructions?|messages?|rules|configuration|directives|guidelines|context)\b/, 'Asks for the system prompt or hidden instructions.'),
  R('your-instructions', 'extraction', 0.6, /\b(?:repeat|reveal|print|show|output|dump|recite|disclose|paste|echo|tell me|list)\b[^.\n]{0,20}\byour (?:instructions|prompt|rules|guidelines|directives|configuration)\b/, 'Asks the model to print its own instructions.'),
  R('text-above', 'extraction', 0.7, /\b(?:repeat|print|output|copy|write|show|echo|return)\b[^.\n]{0,30}\b(?:everything|all|the (?:text|words|content|lines|messages?|conversation))\b[^.\n]{0,20}\b(?:above|before this|preceding|prior|so far|from the (?:beginning|start|top))\b|\b(?:text|words|sentence|message|lines?) (?:above|before) (?:starting|beginning) with\b/, 'Asks for the text that came before the user turn.'),
  R('start-with-you-are', 'extraction', 0.5, /\bstart(?:ing)?\s+(?:your\s+(?:answer|response|reply)\s+)?with\s+["']?you are (?:a|an|the)\b|\bbegins? with ["']you are\b/, 'Fishes for a prompt that begins "You are ...".'),
  R('how-instructed', 'extraction', 0.5, /\bwhat (?:were|are|have) you (?:been )?(?:told|instructed|programmed|configured|prompted)\b|\bhow (?:were|are) you (?:instructed|programmed|configured|prompted)\b/, 'Asks what the model was told to do.'),
  R('transform-prompt', 'extraction', 0.75, /\b(?:translate|summari[sz]e|encode|convert|rewrite|paraphrase|base64)\b[^.\n]{0,30}\byour (?:system |initial |original |hidden )?(?:prompt|instructions|rules)\b/, 'Asks for the prompt in a transformed form to dodge filters.'),
  R('canary-fishing', 'extraction', 0.55, /\b(?:canary|secret|hidden|magic|internal)\s+(?:[\w-]+\s+)?(?:token|word|code|password|key|phrase)\b[^.\n]{0,30}\b(?:is|reveal|tell|print|say|what|share)\b/, 'Asks for a hidden token.'),
  // --- fake turns and role tags
  R('chat-template-tokens', 'role-injection', 0.7, /<\|?(?:im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\|?>/, 'Raw chat-template control tokens.'),
  R('fake-role-turn', 'role-injection', 0.55, /(?:^|\n)\s*(?:#{1,4}\s*)?\[?(?:system|assistant|developer|admin)\]?\s*(?:prompt|message|instruction|override|note)?\s*:\s*(?:you|ignore|from now|new|the (?:user|assistant)|override|disregard|important|attention|reveal|forget|as an? |always|never|do not)/, 'A forged "system:" or "assistant:" turn.'),
  R('role-tags', 'role-injection', 0.55, /<\/?(?:system|assistant|developer|instructions?|admin|sys|system_prompt)>|\[(?:system|assistant|developer|admin)\]|\[\/?inst\]/, 'Forged role tags.'),
  R('fake-system-block', 'role-injection', 0.6, /(?:-{3,}|={3,}|#{2,}|\*{3,})\s*(?:begin|start|end)?\s*(?:of\s+)?(?:system|developer|admin)\s*(?:prompt|message|instructions?)\b/, 'A forged "system prompt" block.'),
  R('context-boundary', 'role-injection', 0.3, /\b(?:end of|begin|start of) (?:user input|context|prompt|system prompt|untrusted (?:content|data)|instructions)\b|-{3,}\s*(?:end|begin|new) (?:of )?(?:instructions|prompt|system)/, 'Pretends the data has ended and instructions begin.'),
  // --- authority claims
  R('authority-claim', 'authority', 0.3, /\b(?:i am|i'm|this is|we are|message from|sent by)\s+(?:your|the|an?)?\s*(?:developers?|creators?|admin|administrator|sysadmin|operators?|owners?|openai|anthropic|google|security team|it department|system administrator|ai provider|model provider)\b/, 'Claims to be the developer or an admin.'),
  R('admin-override', 'authority', 0.55, /\b(?:admin|administrator|developer|root|sudo|god|maintenance|debug|override|emergency|superuser)\s+(?:override|access|mode|privileges|command|authori[sz]ation|clearance)\b[^.\n]{0,20}\b(?:granted|enabled|activated|engaged|confirmed|code|accepted|on)\b/, 'Announces an "admin override".'),
  R('authorized-by', 'authority', 0.35, /\b(?:authori[sz]ed|approved|sanctioned|cleared|permitted) by (?:the )?(?:admin|administrator|developers?|security(?: team)?|management|ceo|cto|system|openai|anthropic|your (?:owner|operator|creator))\b/, 'Claims prior authorisation.'),
  R('priority-override', 'authority', 0.45, /\b(?:priority|urgent|critical|important|mandatory|official)\s*:?\s*(?:override|instruction|directive|system (?:message|notice|update|instruction)|security (?:update|notice) for (?:the )?(?:ai|assistant|model))\b/, 'Dresses an instruction up as a priority system notice.'),
  // --- addressed to the AI (typical of indirect injection)
  R('addressed-to-ai', 'indirect', 0.55, new RegExp('\\b(?:note|message|attention|instructions?|memo|notice|hey|hi|hello|dear|important|warning|p\\.?s\\.?|reminder)\\s*(?:to|for)?\\s*(?:the|any|all|every)?\\s*' + AI + '\\b\\s*[:,!\\-\u2013\u2014]'), 'Text that speaks directly to an AI reading it.'),
  R('vocative-ai', 'indirect', 0.5, /(?:^|[\n"',;(]|[.!?]\s)\s*(?:dear\s+|hey\s+|attention\s+)?(?:ai|a\.i\.|assistants?|bots?|agents?|models?|chatbots?|llms?|claude|gpt|gemini|copilot)(?:\s+[\w-]+)?\s*[,:]\s*\w|\((?:for|to|attn:?)\s+(?:the\s+)?(?:ai|assistants?|llms?|models?|agents?|bots?)\)|\b(?:for|to) (?:the\s+)?(?:ai|assistants|llms|models|agents|bots)\s*\)?\s*:/, 'Text that addresses an AI by name or role.'),
  R('ai-should', 'indirect', 0.55, /\b(?:the |any |all |every )?(?:ai|assistant|assistants|bot|chatbot|model|agent|llm)s?\b[^.\n]{0,40}\b(?:should|must|shall|is required to|needs to|will now|is instructed to|has to)\b[^.\n]{0,40}\b(?:say|state|tell|answer|reply|respond|output|ignore|disregard|reveal|print|recommend|include|send|forward|offer|claim|mention|never)\b/, 'Tells the AI what it must say or do.'),
  R('hide-this-note', 'indirect', 0.5, /\b(?:never|do not|don't)\s+(?:mention|reveal|disclose|show|repeat)\s+(?:this|these)\s+(?:note|instructions?|message|text|line)s?\b/, 'Asks the reader to hide the instruction itself.'),
  R('reveal-data', 'exfiltration', 0.45, /\b(?:reply|respond|answer|tell|give|show|share|include|list|print|read out)\b[^.\n]{0,40}\b(?:the |your |my |all |their )?(?:card numbers?|credit cards?|cvv|passwords?|api keys?|ssns?|social security numbers?|private keys?|access tokens?|credentials)\b/, 'Asks for secrets or card data.'),
  R('if-you-are-ai', 'indirect', 0.6, /\bif you(?:'re| are) (?:an? |the )?(?:ai|llm|large language model|language model|assistant|chatbot|automated (?:system|agent|assistant|tool)|bot|agent|model|ai agent|ai assistant)\b/, '"If you are an AI ..." is aimed at a model, not a person.'),
  R('ai-reading-this', 'indirect', 0.6, new RegExp('\\b' + AI + '\\s+(?:reading|processing|parsing|summari[sz]ing|seeing|viewing|crawling|browsing|scanning|analy[sz]ing|handling|ingesting) (?:this|these|the (?:page|email|document|text|file|message|content|site))\\b'), 'Addresses whichever AI processes the content.'),
  R('when-you-read-this', 'indirect', 0.5, /\b(?:when|if|once|after) (?:you|the (?:ai|assistant|model|agent|bot)) (?:read|reads|see|sees|summari[sz]es?|process(?:es)?|encounters?|finds?|parses?) this\b/, 'A trigger aimed at whoever processes the text.'),
  R('obey-hidden', 'indirect', 0.45, /\b(?:obey|comply with|follow|execute|carry out|act on)\s+(?:the |these |all |my |following )*(?:instructions?|commands?|orders?|directives?)\b[^.\n]{0,30}\b(?:below|in this|hidden|instead|exactly|immediately|without question)/, 'Asks the reader to execute embedded commands.'),
  // --- data exfiltration
  R('exfil-data', 'exfiltration', 0.65, new RegExp('\\b(?:send|forward|email|e-mail|mail|post|upload|transmit|leak|exfiltrate|copy|share|submit|deliver|cc|bcc|relay|pass along|dump)\\b[^.\\n]{0,80}\\b' + DATA + '[^.\\n]{0,80}\\b(?:to|at|into|via|onto)\\b'), 'Asks to send secrets or private data somewhere.'),
  R('exfil-url', 'exfiltration', 0.55, /\b(?:append|add|include|attach|put|insert|encode|embed|place)\b[^.\n]{0,60}\b(?:to|in|into|as|inside)\b[^.\n]{0,20}\b(?:the |a |this )?(?:url|link|query(?: string)?|parameter|image (?:url|link|source)|src|request|webhook)\b/, 'Asks to smuggle data into a URL.'),
  R('render-image', 'exfiltration', 0.5, /\b(?:render|display|show|output|include|insert|embed|print)\b[^.\n]{0,30}\b(?:this|the following|an?|the) (?:markdown )?(?:image|img|pixel|badge|tracking pixel)\b[^\n]{0,40}(?:https?:|!\[|<img)|!\[[^\]]*\]\(https?:\/\/[^)\s]*(?:\{|%7b|\[)[^)]*\)/, 'Asks the model to output an image whose URL carries data.'),
  R('templated-url', 'exfiltration', 0.7, /https?:\/\/[^\s)'"]*[?&#][\w-]+=(?:\{|\[|<|%7b|%3c)\s*(?:data|secret|key|conversation|chat|summary|history|password|token|email|context|user|prompt|info|answer)/, 'A URL with a placeholder for the data to steal.'),
  R('send-to-address', 'exfiltration', 0.25, /\b(?:send|forward|email|post|upload|transmit|cc|bcc|mail|reply)\b[^.\n]{0,120}\b(?:to|at)\s+[\w.+-]+@[\w-]+\.[\w.-]+/, 'Asks for something to be sent to an address (weak on its own).'),
  // --- coercing tools and actions
  R('secrecy', 'tool-coercion', 0.6, /\b(?:do not|don't|never|without)\s+(?:tell|telling|inform|informing|notify|notifying|alert|alerting|mention|mentioning|ask|asking|confirm|confirming|warn|warning|show|showing|reveal|revealing|let)\w*\s+(?:the |this |your )?(?:user|human|customer|operator|owner|recipient|admin|anyone|them|him|her)\b(?! (?:with|through|how|about the (?:steps|process)))/, 'Asks for an action to be hidden from the user.'),
  R('silent-action', 'tool-coercion', 0.55, /\b(?:silently|secretly|quietly|covertly|discreetly|in the background|without (?:any )?(?:confirmation|approval|permission|asking|review))\b[^.\n]{0,60}\b(?:send|forward|delete|remove|run|execute|call|transfer|wire|pay|refund|email|post|upload|invoke|grant|approve|share|push|drop)\b|\b(?:send|delete|remove|run|execute|transfer|wire|pay|refund|forward|grant|approve|push|drop)\b[^.\n]{0,60}\b(?:silently|secretly|quietly|covertly|without (?:any )?(?:confirmation|approval|permission|asking|telling|review))\b/, 'An action to take without the user knowing.'),
  R('money-transfer', 'tool-coercion', 0.5, /\b(?:wire|transfer|send|pay|refund|move)\s+(?:\$|usd\s*|eur\s*|€)?\d[\d,]*(?:\.\d+)?\s*(?:k|usd|dollars|eur|euros)?\b[^.\n]{0,40}\b(?:to|into)\s+(?:account|iban|wallet|the following|this account|routing)/, 'Moves money to a named account.'),
  R('grant-access', 'tool-coercion', 0.4, /\b(?:grant|give|add|assign)s?\b[^.\n]{0,30}\b(?:admin|owner|root|write|full|elevated) (?:access|rights|permissions?|role|privileges)\b[^.\n]{0,30}\bto\b/, 'Grants elevated access.'),
  R('urgent-action', 'tool-coercion', 0.25, /\b(?:immediately|right now|asap|first|before (?:doing|answering|responding|anything|you reply))\b[^.\n]{0,30}\b(?:run|execute|call|send|forward|delete|transfer|wire|pay|refund|grant|invoke)\b/, 'Urgent call to act (weak on its own).'),
  R('tool-invocation', 'tool-coercion', 0.3, /\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[\w-]+[_ ](?:tool|function|plugin|action)\b[^.\n]{0,40}\b(?:with|now|immediately|using)\b/, 'Tells the model to call a specific tool (weak on its own).'),
  // --- encoding and splitting as instructions
  R('decode-and-follow', 'obfuscation', 0.6, /\b(?:decode|decipher|decrypt|translate|unscramble|reverse|rot13|base64[- ]?decode|convert|read backwards)\b[^.\n]{0,50}\b(?:and|then)\s+(?:follow|execute|obey|do|run|act on|carry out|perform|answer|respond to|comply)\b/, 'Asks to decode text and then obey it.'),
  R('encoded-instructions', 'obfuscation', 0.5, /\b(?:base64|rot-?13|hex|binary|morse|caesar|cipher|reversed|backwards|encoded)\b[^.\n]{0,60}\b(?:instructions?|commands?|message|text|string|payload)\b[^.\n]{0,40}\b(?:follow|execute|obey|do|run|comply)/, 'Refers to encoded instructions to follow.'),
  R('payload-split', 'obfuscation', 0.55, /\b(?:concatenate|combine|join|merge|put together|glue|assemble)\b[^.\n]{0,60}\b(?:and|then)\s+(?:follow|execute|do|answer|respond|obey|run|treat|perform)\b|\b(?:[a-z]|s\d|part\s?\d)\s*\+\s*(?:[a-z]|s\d|part\s?\d)\b[^.\n]{0,40}\b(?:follow|execute|obey|run|instruction|answer it|do it|respond to)/, 'Builds an instruction from pieces to slip past filters.'),
  // --- other languages (run on the native-script view)
  R('override-es', 'multilingual', 0.8, /\b(?:ignora|olvida|omite|descarta)(?:r)?\s+(?:todas?\s+)?(?:las\s+|tus\s+)?(?:instrucciones|reglas|indicaciones)\s+(?:anteriores|previas|originales)/, 'Spanish: ignore previous instructions.'),
  R('override-fr', 'multilingual', 0.8, /\b(?:ignore[rz]?|oublie[rz]?)\s+(?:toutes\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|règles)\s+(?:précédentes|antérieures|initiales)/, 'French: ignore previous instructions.'),
  R('override-de', 'multilingual', 0.8, /\b(?:ignorier(?:e|en sie|t)?|vergiss|vergessen sie)\s+(?:alle\s+)?(?:deine\s+|ihre\s+|die\s+)?(?:vorherigen|bisherigen|vorigen|obigen|ursprünglichen)\s+(?:anweisungen|instruktionen|regeln|befehle)/, 'German: ignore previous instructions.'),
  R('override-pt', 'multilingual', 0.8, /\b(?:ignore|ignora|esqueça|esqueca|desconsidere)\s+(?:todas\s+)?(?:as\s+)?(?:instruções|instrucoes|regras)\s+(?:anteriores|prévias|previas)/, 'Portuguese: ignore previous instructions.'),
  R('override-it', 'multilingual', 0.8, /\b(?:ignora|dimentica)\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole)\s+(?:precedenti|originali)/, 'Italian: ignore previous instructions.'),
  R('override-nl', 'multilingual', 0.8, /\b(?:negeer|vergeet)\s+(?:alle\s+)?(?:de\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|regels)/, 'Dutch: ignore previous instructions.'),
  R('override-ru', 'multilingual', 0.8, /(?:игнорируй(?:те)?|забудь(?:те)?|проигнорируй(?:те)?)\s+(?:все\s+)?(?:предыдущие|прежние|прошлые|свои)\s+(?:инструкции|указания|правила)/, 'Russian: ignore previous instructions.'),
  R('override-zh', 'multilingual', 0.8, /(?:忽略|无视|忘记|忽视)(?:掉)?(?:你)?(?:之前|以前|上面|先前|所有|前面)(?:的)?(?:所有)?(?:的)?(?:指令|指示|说明|规则|提示)/, 'Chinese: ignore previous instructions.'),
  R('override-ja', 'multilingual', 0.8, /(?:以前|前|これまで|上記)の(?:指示|命令|ルール)(?:を|は)(?:すべて|全て)?(?:無視|忘れ)/, 'Japanese: ignore previous instructions.'),
  R('override-ko', 'multilingual', 0.8, /이전(?:의)?\s*(?:모든\s*)?(?:지시|지침|명령|규칙)(?:사항)?(?:을|를)?\s*(?:모두\s*)?(?:무시|잊어)/, 'Korean: ignore previous instructions.'),
  R('override-hi', 'multilingual', 0.8, /(?:पिछले|पहले के)\s+(?:सभी\s+)?(?:निर्देशों|निर्देश|नियमों)\s+(?:को\s+)?(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)/, 'Hindi: ignore previous instructions.'),
  R('override-tr', 'multilingual', 0.8, /önceki\s+(?:tüm\s+)?(?:talimatları|talimatlari|kuralları)\s+(?:yok say|unut|görmezden gel)/, 'Turkish: ignore previous instructions.'),
  R('override-ar', 'multilingual', 0.8, /(?:تجاهل|انس)\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الأوامر)\s+(?:السابقة)/, 'Arabic: ignore previous instructions.'),
  R('extraction-ml', 'multilingual', 0.7, /(?:muestra|revela|imprime|dime)\s+(?:tu|el)\s+(?:prompt|mensaje|instrucciones)\s+(?:del\s+)?(?:sistema|inicial)|(?:montre|révèle|affiche)[- ]?(?:moi)?\s+(?:ton|votre|le)\s+(?:prompt|message)\s+(?:système|systeme|initial)|(?:zeige?|verrate|gib)\s+(?:mir\s+)?(?:deinen|ihren|den)\s+(?:system-?prompt|systemprompt|anweisungen)|(?:покажи|выведи|раскрой)\s+(?:свой\s+|свои\s+)?(?:системный\s+промпт|системные\s+инструкции)|(?:显示|告诉我|输出|打印)(?:你的)?(?:系统提示|系统提示词|初始指令)/, 'Asks for the system prompt in another language.')
];
const COMPACT = /(?:ignore|disregard|forget|bypass|override)(?:all|the|your|any|of)*(?:previous|prior|above|earlier|system|safety)(?:instructions?|rules|prompts?|guidelines|directives)|(?:reveal|print|show|repeat|dump)(?:me)?(?:your|the)(?:system|hidden|initial|original)(?:prompt|instructions)|doanythingnow|youarenowdan|developermodeenabled|jailbreakmode/;
const DISCUSSION = /\b(?:prompt injections?|injection attacks?|jailbreak(?:s|ing)?|attack(?:s|er|ers)?|adversar\w+|red[- ]team\w*|for (?:example|instance)|e\.g\.|such as|phrases? like|strings? like|payloads?|researchers?|security|vulnerabilit\w+|defen[cs]\w*|detect\w*|classifier|mitigat\w+|owasp|threat model|malicious|unit tests?|test cases?|test suite|regex(?:es|p)?|blocklists?|denylists?|the string|this string|samples?|examples?|phishing|scams?|fraud\w*|awareness|training|warning signs|filter(?:s|ing)?|guardrails?|known (?:trick|technique)s?|this (?:article|post|paper|talk|guide|tutorial|course))\b/g;
function quotedSpans(t) { const out = []; for (const m of t.matchAll(/"[^"\n]{3,300}"|'[^'\n]{6,300}'|`[^`\n]{3,300}`|```[\s\S]*?```|\u201c[^\u201d\n]{3,300}\u201d|\u00ab[^\u00bb\n]{3,300}\u00bb/g)) out.push([m.index, m.index + m[0].length]); return out; }
const FLAG_EMOJI_TAGS = /\u{1F3F4}[\u{E0061}-\u{E007A}]{2,7}\u{E007F}/gu;
const noisyOr = (ws) => 1 - ws.reduce((p, w) => p * (1 - Math.max(0, Math.min(1, w))), 1);
/** Detect instruction-like text.
 *  o.block / o.flag: thresholds (default 0.7 / 0.4). o.source: 'user' (default) or an untrusted source; untrusted
 *  content is held to a stricter standard because data should never address the model. Returns
 *  { score, verdict: 'allow'|'flag'|'block', hits: [...], signals: {...} }. */
export function detect(text, o = {}) {
  const raw = String(text ?? '');
  const block = o.block ?? 0.7; const flag = o.flag ?? 0.4; const untrusted = !!o.source && o.source !== 'user' && o.source !== 'system';
  if (!raw.trim()) return { score: 0, verdict: 'allow', hits: [], signals: {} };
  const t0 = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const vs = views(raw.length > 200000 ? raw.slice(0, 200000) : raw, { decode: o.decode !== false });
  const plain = raw.toLowerCase().replace(/[‘’‚‛′`´]/g, "'").replace(/[“”„‟″]/g, '"').replace(/[‐‑‒–—―]/g, '-').replace(/[ \t\u00A0]+/g, ' ');
  const best = new Map();
  for (const v of vs) {
    if (v.compact) continue;
    for (const r of RULES) {
      r.re.lastIndex = 0; const m = r.re.exec(v.text); if (!m) continue;
      const prev = best.get(r.id);
      if (!prev || (prev.obfuscated && !v.obfuscated)) best.set(r.id, { rule: r.id, category: r.cat, weight: r.w, layer: v.layer, obfuscated: v.obfuscated, match: m[0].slice(0, 160), index: v.layer === 'text' ? m.index : -1, why: r.why, viewText: v.text });
    }
  }
  const cv = vs.find((v) => v.compact);
  if (cv && ![...best.values()].some((h) => ['override', 'extraction', 'jailbreak', 'multilingual'].includes(h.category))) { const m = COMPACT.exec(cv.text); if (m) best.set('compact-signature', { rule: 'compact-signature', category: 'obfuscation', weight: 0.7, layer: 'compact', obfuscated: true, match: m[0], index: -1, why: 'A known attack phrase spelled out with spaces, dots or symbols between the letters.' }); }
  const hits = []; const signals = {};
  const disc = ((canonDiscussion(vs[0].text)) || []).length; const qs = quotedSpans(vs[0].text);
  signals.discussion = disc;
  for (const h of best.values()) {
    let eff = h.weight; let note = '';
    if (h.obfuscated) note = 'found only after decoding (' + h.layer + ')';
    else { r0(h); if (!h.plainMatch) note = 'hidden with look-alike or invisible characters'; }
    if (!h.obfuscated && disc >= 2) {
      const inQuote = h.index >= 0 && qs.some(([a, b]) => h.index >= a && h.index < b);
      eff *= inQuote ? 0.2 : 0.45; h.dampened = true; note = (note ? note + '; ' : '') + (inQuote ? 'quoted inside text that discusses attacks (down-weighted)' : 'appears in text that discusses attacks (down-weighted)');
    }
    if (untrusted && h.category !== 'jailbreak' && !h.dampened) eff = Math.min(0.95, eff * 1.2);
    hits.push({ rule: h.rule, category: h.category, weight: h.weight, effective: Math.round(eff * 1000) / 1000, layer: h.layer, match: h.match, why: h.why, note, dampened: !!h.dampened });
  }
  function r0(h) { const r = RULES.find((x) => x.id === h.rule); r.re.lastIndex = 0; h.plainMatch = r.re.test(plain); }
  // obfuscation signals in their own right
  const inv = countInvisible(raw.replace(FLAG_EMOJI_TAGS, ''));
  const tagText = raw.replace(FLAG_EMOJI_TAGS, '').match(TAG_RE) || [];
  if (tagText.length >= 4) hits.push({ rule: 'unicode-tag-smuggling', category: 'obfuscation', weight: 0.6, effective: 0.6, layer: 'text', match: tagText.length + ' invisible tag characters', why: 'Invisible Unicode tag characters can carry a hidden ASCII message.', note: '' });
  const bidiOverrides = (raw.match(/[\u202A-\u202E\u2066-\u2069]/g) || []).length;
  if (bidiOverrides) hits.push({ rule: 'bidi-control', category: 'obfuscation', weight: 0.35, effective: 0.35, layer: 'text', match: bidiOverrides + ' bidirectional override character(s)', why: 'Bidirectional overrides make text display differently from how it is read.', note: '' });
  if (inv.zeroWidth >= 2 && /\p{L}[\u200B-\u200D\u2060\uFEFF\u00AD]+\p{L}/u.test(raw)) hits.push({ rule: 'zero-width-chars', category: 'obfuscation', weight: 0.25, effective: 0.25, layer: 'text', match: inv.zeroWidth + ' zero-width character(s) inside words', why: 'Zero-width characters inside words are used to split keywords.', note: '' });
  const mixed = mixedScriptWords(raw); if (mixed.length) hits.push({ rule: 'mixed-script', category: 'obfuscation', weight: 0.3, effective: 0.3, layer: 'text', match: mixed.slice(0, 3).join(', '), why: 'Words that mix Latin with Cyrillic or Greek letters, a filter-evasion trick.', note: '' });
  const instr = hits.filter((h) => h.category !== 'obfuscation');
  const evasive = instr.filter((h) => /decoding|look-alike/.test(h.note));
  if (evasive.length) hits.push({ rule: 'evasion', category: 'obfuscation', weight: 0.4, effective: 0.4, layer: evasive[0].layer, match: evasive.map((h) => h.rule).join(', '), why: 'An instruction was disguised; disguising instructions is itself a strong signal.', note: '' });
  const damp = hits.filter((h) => h.dampened); const full = hits.filter((h) => !h.dampened);
  const dampScore = damp.length ? Math.min(1, Math.max(...damp.map((h) => h.effective)) + 0.05 * (damp.length - 1)) : 0;
  const score = Math.round(noisyOr(full.map((h) => h.effective).concat(dampScore ? [dampScore] : [])) * 1000) / 1000;
  hits.sort((a, b) => b.effective - a.effective);
  const verdict = score >= block ? 'block' : score >= flag ? 'flag' : 'allow';
  const ms = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0;
  return { score, verdict, hits, signals: Object.assign(signals, { invisible: inv, views: vs.length }), ms };
}
function canonDiscussion(t) { DISCUSSION.lastIndex = 0; return t.match(DISCUSSION); }
/* Split text into sentences/lines and report the instruction-like ones (used to quarantine parts of untrusted content). */
export function scanSentences(text, o = {}) {
  const s = String(text ?? ''); const out = [];
  const parts = s.split(/(?<=[.!?\u3002\uff01\uff1f])\s+|\n+/);
  let pos = 0;
  for (const p of parts) {
    const idx = s.indexOf(p, pos); if (idx >= 0) pos = idx + p.length;
    if (!p.trim()) continue;
    const d = detect(p, Object.assign({}, o, { decode: true }));
    if (d.verdict !== 'allow') out.push({ text: p, index: idx, score: d.score, verdict: d.verdict, hits: d.hits });
  }
  return out;
}
export function explain(result) {
  if (!result || !result.hits || !result.hits.length) return 'No instruction-like patterns found.';
  return result.hits.slice(0, 6).map((h) => h.rule + ' (' + h.effective + (h.note ? ', ' + h.note : '') + '): ' + h.why).join('\n');
}
