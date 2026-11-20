import { CheckResult } from "../models";
import { Detector } from "./base";

const SCORE_THRESHOLD = 0.6;

const PATTERNS: [RegExp, number, string][] = [
  [/ignor\w*\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directives?)/i, 1.0, "instruction override"],
  [/disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i, 1.0, "instruction override"],
  [/forget\s+(everything|all)\s+(above|before|you.?ve been told)/i, 1.0, "instruction override"],
  [/your\s+(real|true|actual|new)\s+(instructions?|directives?|prompt|task)\s+(are|is)/i, 0.9, "hidden instruction injection"],
  [/you\s+are\s+now\s+(a|an)\s+(?!helpful|an AI|a language)/i, 0.8, "persona override attempt"],
  [/override\s+(your\s+)?(system\s+prompt|instructions?|guidelines?|restrictions?)/i, 1.0, "system prompt override"],
  [/(print|reveal|show|output|display|repeat|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial prompt)/i, 0.9, "system prompt extraction"],
  [/what (are|were) your (original |initial |exact |full )?(instructions?|system prompt|directives?)/i, 0.8, "system prompt extraction"],
  [/<\/?(system|human|assistant|user|instruction)>/i, 0.9, "XML/tag injection"],
  [/\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>/i, 0.9, "LLM format injection"],
  [/(translate|summarise|summarize)\s+the\s+(above|following|text)\s+(into|as)\s+instructions?/i, 0.7, "indirect injection via translation"],
  [/from now on\s+(you|your).{0,30}(ignore|forget|disregard)/i, 0.9, "persistent instruction override"],
  // French, and fake role lines a message can carry to pass as the conversation
  // (a line starts after any separator, \r and U+2028 included).
  [/ignor\w*\s+(toutes?\s+)?(les\s+|tes\s+|vos\s+)?(instructions?|consignes?|directives?)\s+(pr[ée]c[ée]dentes?|ant[ée]rieures?|ci-dessus)/im, 1.0, "instruction override"],
  [/oublie[sz]?\s+(tout\s+ce\s+qui\s+pr[ée]c[èe]de|(toutes\s+)?(tes|vos|les)\s+(instructions?|consignes?|directives?))/im, 1.0, "instruction override"],
  [/(tes|vos)\s+(vraies|v[ée]ritables|nouvelles)\s+(instructions?|consignes?|directives?|t[âa]ches?)\s+(sont|est)/im, 0.9, "hidden instruction injection"],
  [/(tu\s+es|vous\s+[êe]tes)\s+(d[ée]sormais|maintenant)\s+(un|une)\s+/im, 0.8, "persona override attempt"],
  [/contourne[sz]?\s+(tes|vos)\s+(instructions?|consignes?|r[èe]gles|restrictions?|prompt\s+syst[èe]me)/im, 1.0, "system prompt override"],
  [/(affiche|r[ée]v[èe]le|montre|r[ée]p[èe]te|donne)[sz]?(-moi)?\s+(ton|votre|tes|vos)\s+(prompt\s+syst[èe]me|instructions?\s+initiales|consignes?\s+initiales|instructions?|consignes?)/im, 0.9, "system prompt extraction"],
  [/[àa]\s+partir\s+de\s+maintenant.{0,40}(ignore|oublie)/im, 0.9, "persistent instruction override"],
  [/(?:^|[\r\u2028\u2029])[^\S\r\n\u2028\u2029]*(system|syst[èe]me|assistant)[^\S\r\n\u2028\u2029]*:[^\S\r\n\u2028\u2029]*.{0,80}\b(please|ignore|send|forward|reply|envoie|transf[èe]re|r[ée]ponds|oublie)/im, 0.8, "fake role line"],
];

export class PromptInjectionDetector extends Detector {
  readonly name     = "prompt_injection";
  readonly severity = "high" as const;

  check(text: string): CheckResult {
    let bestScore  = 0;
    let bestReason = "";
    let bestMatch  = "";
    for (const [pat, score, reason] of PATTERNS) {
      const m = pat.exec(text);
      if (m && score > bestScore) {
        bestScore  = score;
        bestReason = reason;
        bestMatch  = m[0];
      }
    }
    if (bestScore >= SCORE_THRESHOLD) return this._block(bestScore, bestReason, bestMatch);
    return this._pass();
  }
}
