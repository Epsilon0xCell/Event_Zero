"""Flesch readability for the ELI5 layer. Design target (labelled as a design
target, not a sourced standard): FRE >= 80, FK grade <= 6."""
import re
def _syllables(w):
    w=re.sub(r'[^a-z]','',w.lower())
    if not w: return 0
    n=len(re.findall(r'[aeiouy]+', w)); 
    if w.endswith('e') and n>1: n-=1
    return max(n,1)
def scores(sentences):
    text=" ".join(sentences); words=text.split()
    if not words or not sentences: return {"flesch_reading_ease": 0, "flesch_kincaid_grade": 0}
    asl=len(words)/len(sentences); asw=sum(_syllables(w) for w in words)/len(words)
    fre=206.835-1.015*asl-84.6*asw; fk=0.39*asl+11.8*asw-15.59
    return {"flesch_reading_ease": round(fre,1), "flesch_kincaid_grade": round(fk,1),
            "design_target": "FRE >= 80 and FK <= 6 (Event Zero design target, labelled as such)",
            "meets_design_target": fre>=80 and fk<=6}
