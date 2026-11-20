"""Prompt injection detector — regex + heuristic patterns, sub-1ms."""
import re
from ..models import CheckResult
from .base import Detector

# Each tuple: (pattern, score, reason)
_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"ignor\w*\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directives?)", re.I), 1.0, "instruction override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.I), 1.0, "instruction override"),
    (re.compile(r"forget\s+(everything|all)\s+(above|before|you.?ve been told)", re.I), 1.0, "instruction override"),
    (re.compile(r"your\s+(real|true|actual|new)\s+(instructions?|directives?|prompt|task)\s+(are|is)", re.I), 0.9, "hidden instruction injection"),
    (re.compile(r"you\s+are\s+now\s+(a|an)\s+(?!helpful|an AI|a language)", re.I), 0.8, "persona override attempt"),
    (re.compile(r"override\s+(your\s+)?(system\s+prompt|instructions?|guidelines?|restrictions?)", re.I), 1.0, "system prompt override"),
    (re.compile(r"(print|reveal|show|output|display|repeat|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial prompt)", re.I), 0.9, "system prompt extraction"),
    (re.compile(r"what (are|were) your (original |initial |exact |full )?(instructions?|system prompt|directives?)", re.I), 0.8, "system prompt extraction"),
    (re.compile(r"</?(system|human|assistant|user|instruction)>", re.I), 0.9, "XML/tag injection"),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I), 0.9, "LLM format injection"),
    (re.compile(r"(translate|summarise|summarize)\s+the\s+(above|following|text)\s+(into|as)\s+instructions?", re.I), 0.7, "indirect injection via translation"),
    (re.compile(r"from now on\s+(you|your).{0,30}(ignore|forget|disregard)", re.I), 0.9, "persistent instruction override"),
    # French, and fake role lines a message can carry to pass as the conversation
    (re.compile(r"ignor\w*\s+(toutes?\s+)?(les\s+|tes\s+|vos\s+)?(instructions?|consignes?|directives?)\s+(pr[ée]c[ée]dentes?|ant[ée]rieures?|ci-dessus)", re.I | re.M), 1.0, "instruction override"),
    (re.compile(r"oublie[sz]?\s+(tout\s+ce\s+qui\s+pr[ée]c[èe]de|(toutes\s+)?(tes|vos|les)\s+(instructions?|consignes?|directives?))", re.I | re.M), 1.0, "instruction override"),
    (re.compile(r"(tes|vos)\s+(vraies|v[ée]ritables|nouvelles)\s+(instructions?|consignes?|directives?|t[âa]ches?)\s+(sont|est)", re.I | re.M), 0.9, "hidden instruction injection"),
    (re.compile(r"(tu\s+es|vous\s+[êe]tes)\s+(d[ée]sormais|maintenant)\s+(un|une)\s+", re.I | re.M), 0.8, "persona override attempt"),
    (re.compile(r"contourne[sz]?\s+(tes|vos)\s+(instructions?|consignes?|r[èe]gles|restrictions?|prompt\s+syst[èe]me)", re.I | re.M), 1.0, "system prompt override"),
    (re.compile(r"(affiche|r[ée]v[èe]le|montre|r[ée]p[èe]te|donne)[sz]?(-moi)?\s+(ton|votre|tes|vos)\s+(prompt\s+syst[èe]me|instructions?\s+initiales|consignes?\s+initiales|instructions?|consignes?)", re.I | re.M), 0.9, "system prompt extraction"),
    (re.compile(r"[àa]\s+partir\s+de\s+maintenant.{0,40}(ignore|oublie)", re.I | re.M), 0.9, "persistent instruction override"),
    (re.compile(r"^[^\S\n]*(system|syst[èe]me|assistant)[^\S\n]*:[^\S\n]*.{0,80}\b(please|ignore|send|forward|reply|envoie|transf[èe]re|r[ée]ponds|oublie)", re.I | re.M), 0.8, "fake role line"),
]

_SCORE_THRESHOLD = 0.6

# Every line separator str.splitlines knows becomes \n before matching:
# a role line starts after any of them.
_LINE_BREAK = re.compile(r"\r\n?|[\v\f\x1c-\x1e\x85\u2028\u2029]")


class PromptInjectionDetector(Detector):
    name     = "prompt_injection"
    severity = "high"

    def check(self, text: str) -> CheckResult:
        text        = _LINE_BREAK.sub("\n", text)
        best_score  = 0.0
        best_reason = ""
        best_match  = ""
        for pat, score, reason in _PATTERNS:
            m = pat.search(text)
            if m and score > best_score:
                best_score  = score
                best_reason = reason
                best_match  = m.group(0)
        if best_score >= _SCORE_THRESHOLD:
            return self._block(best_score, best_reason, best_match)
        return self._pass()
