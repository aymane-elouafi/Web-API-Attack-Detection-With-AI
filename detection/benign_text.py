"""Hard negatives for the payload classifier: harmless text that LOOKS like an attack to a model
that only counts punctuation (apostrophes, dashes, quotes, < >, %, SQL/HTML-looking words, code,
URLs, e-mails, accents). Generated from templates; every text carries its template id so training
and validation can be split by template family (no near-duplicate leakage).

None of these is an injection: no quote-then-OR tautologies, no <script>/event handlers, no ../ .
"""
import random

_NAMES = ["O'Brien", "D'Angelo", "Zoë", "José", "François", "Müller", "Søren", "Nguyễn", "Łukasz", "Chloé", "Renée",
          "Seán", "McDonald", "Ben & Jerry's", "AT&T", "H&M", "Levi's", "Marks & Spencer", "Dr. Smith's", "the Joneses'"]
_THINGS = ["laptop", "keyboard", "charger", "backpack", "headphones", "monitor", "desk lamp", "water bottle", "sneakers",
           "tent", "coffee maker", "guitar", "bicycle", "sofa", "blender", "camera", "tripod", "printer", "router", "sunglasses",
           "novel", "cookbook", "jacket", "wallet", "umbrella", "suitcase", "kettle", "toaster", "mouse pad", "notebook"]
_ADJ = ["new", "used", "slim", "waterproof", "wireless", "organic", "vintage", "limited-edition", "non-stick", "ultra-light",
        "made-in-France", "hand-made", "2-in-1", "USB-C", "5G", "eco-friendly", "like-new", "all-purpose"]
_SQL = ["select", "union", "drop", "order", "insert", "update", "delete", "where", "from", "table", "like", "and", "or", "having", "group"]
_PEOPLE = ["alice", "bob.smith", "j.doe+shop", "maria_g", "li.wei", "t.nakamura", "support", "sales-team"]
_DOMAINS = ["example.com", "mail.example.org", "shop.example.co.uk", "my-store.example.net", "exemple.fr"]
_PHRASES = ["it's fine", "see you tomorrow", "don't forget the receipt", "that's all, folks", "what a deal", "we're open late"]
_PKG = ["left-pad", "express", "numpy", "react-dom", "scikit-learn", "lodash"]
_ACCENT = ["café", "naïve", "über", "señor", "crème brûlée", "日本語のレビュー", "Привет, мир", "مرحبا", "안녕하세요", "ça va très bien", "Größe M"]

# Everyday conversational English (apostrophes, quoted words, dashes, abbreviations), unrelated to shopping.
_WORDS = ["weather", "meeting", "train", "movie", "garden", "bus", "lecture", "dinner", "match", "holiday", "exam", "concert", "puzzle", "neighbour", "airport"]
_SAY = ["I can't believe", "Nobody knows why", "She said that", "Do you think", "It's strange that", "We're sure that", "They didn't say whether", "I wonder if"]
_QUOTED = ["maybe", "later", "fine", "good enough", "on time", "no worries", "as planned", "the usual", "bonus", "draft"]
_TIMES = ["noon", "Friday", "next week", "8:30", "tomorrow", "half past six", "the weekend", "March"]


def _i(r) -> str:
    """A product, sometimes with an adjective or an owner in front (keeps the template space large)."""
    t = r.choice(_THINGS)
    x = r.random()
    return f"{r.choice(_ADJ)} {t}" if x < 0.4 else f"{r.choice(_NAMES)} {t}" if x < 0.55 else t


_T = [  # each lambda(r, p) -> text; p = pools bound to the Random r
    lambda r: f"{r.choice(_NAMES)} {_i(r)} -- {r.choice(_ADJ)}, {r.choice(_ADJ)}; ships free!",
    lambda r: f"please {r.choice(_SQL)} your {_i(r)} size - it's {r.choice(_ADJ)}",
    lambda r: f"{_i(r)} for sale -- or best offer ({r.choice(_ADJ)})",
    lambda r: f"the union of {_i(r)} and {_i(r)} sets, {r.randint(2, 9)} pcs",
    lambda r: f"can I drop the {_i(r)} off at the desk? I'm in a hurry...",
    lambda r: f"order {_i(r)} by price: low > high, {r.randint(10, 99)}% off",
    lambda r: f"where is my order #{r.randint(1000, 99999)}? it's been {r.randint(2, 20)} days -- thanks!",
    lambda r: f"{_i(r)} like new -- still in the box ({r.choice(_ADJ)}) & {_i(r)} included",
    lambda r: f"table for {r.randint(2, 8)}, please -- {r.choice(_NAMES)} reservation; no nuts (allergy)",
    lambda r: f"{_i(r)} from ${r.randint(5, 50)} to ${r.randint(51, 400)}.99 - {r.choice(_ADJ)}",
    lambda r: f'he said "{r.choice(_PHRASES)}" and left; she replied \'{r.choice(_PHRASES)}\'',
    lambda r: f"{_i(r)} ({r.choice(_ADJ)}) - size {r.randint(1, 12)}/{r.randint(13, 40)} - {r.choice(_NAMES)}",
    lambda r: f"{r.randint(1, 9)} + {r.randint(1, 9)} = {r.randint(10, 18)}; {r.randint(10, 20)} > {r.randint(1, 9)} and {r.randint(1, 5)} < {r.randint(6, 9)}",
    lambda r: f"loved it!! {r.choice(_PHRASES)}... really <3 {_i(r)} #{_i(r).replace(' ', '')} @{r.choice(_PEOPLE)}",
    lambda r: f"see https://{r.choice(_DOMAINS)}/{_i(r).replace(' ', '-')}?id={r.randint(1, 999)}&ref={r.choice(_PEOPLE)}",
    lambda r: f"mail {r.choice(_PEOPLE)}@{r.choice(_DOMAINS)} or call +{r.randint(1, 99)} {r.randint(100, 999)}-{r.randint(1000, 9999)}",
    lambda r: f"C:\\Users\\{r.choice(_PEOPLE)}\\Documents\\{_i(r).replace(' ', '_')}-{r.randint(1, 20)}.docx",
    lambda r: f"for i in range({r.randint(2, 9)}): print(i * {r.randint(2, 9)})  # {_i(r)}",
    lambda r: f"x = {r.randint(1, 99)} - {r.randint(1, 9)}; y = x / {r.randint(2, 9)}  // {r.choice(_PHRASES)}",
    lambda r: f"if (n > {r.randint(1, 9)} && m < {r.randint(10, 99)}) {{ total += {r.randint(1, 9)}; }}",
    lambda r: f"npm install --save {r.choice(_PKG)} && git commit -m \"add {r.choice(_PKG)}\"",
    lambda r: f"use --{r.choice(['help', 'version', 'verbose', 'dry-run'])} or -{r.choice('vhq')} for more; it's optional",
    lambda r: f"{r.choice(_ACCENT)} {_i(r)} -- {r.choice(_ACCENT)}",
    lambda r: f"{r.choice(_NAMES)}: {r.choice(_ACCENT)} ({r.randint(1, 5)}/5) - {r.choice(_PHRASES)}",
    lambda r: f"2024-{r.randint(1, 12):02d}-{r.randint(1, 28):02d} {r.randint(1, 12)}:{r.randint(10, 59)} pm -- {r.choice(_PHRASES)}",
    lambda r: f"what's the difference between {r.choice(_SQL)} and {r.choice(_SQL)} in {_i(r)} reviews?",
    lambda r: f"I don't think {r.choice(_NAMES)}'s {_i(r)} is worth it, but they're {r.choice(_ADJ)}, aren't they?",
    lambda r: f"{r.randint(1, 8)}\" {_i(r)} / {r.randint(1, 8)}' cable -- {r.randint(5, 80)}% cotton",
    lambda r: f"Q&A: is the {_i(r)} {r.choice(_ADJ)}? yes -- (see p. {r.randint(1, 300)}); no returns!",
    lambda r: f"{r.choice(_SQL)} {_i(r)} {r.choice(_SQL)} {_i(r)} -- {_i(r)}, {_i(r)}",
    lambda r: f"re: {_i(r)} -- {r.choice(_NAMES)} wrote: > {r.choice(_PHRASES)}",
    lambda r: f"{_i(r)}; {_i(r)}; {_i(r)} | {r.choice(_ADJ)} | ~{r.randint(1, 99)} min",
    lambda r: f"price: ${r.randint(1, 99)}.99 (was ${r.randint(100, 199)}.99) -- save {r.randint(5, 60)}%!",
    lambda r: f"{r.choice(_NAMES)} & {r.choice(_NAMES)} -- the {r.choice(_ADJ)} {_i(r)} (v{r.randint(1, 9)}.{r.randint(0, 9)})",
    lambda r: f"how do I {r.choice(['reset', 'return', 'track', 'cancel', 'repair'])} my {_i(r)}? it's {r.choice(_ADJ)}",
    lambda r: f"'{_i(r)}' vs \"{_i(r)}\" -- which one's better?",
    lambda r: f"{_i(r)}->{_i(r)} => {r.choice(_ADJ)} <- {_i(r)}",
    lambda r: f"o'clock {r.randint(1, 12)} -- y'all come back; rock 'n' roll {_i(r)}",
    lambda r: f"{r.choice(_SAY)} the {r.choice(_WORDS)} is moved to {r.choice(_TIMES)} -- who's coming?",
    lambda r: f"His {r.choice(_WORDS)} was '{r.choice(_QUOTED)}' -- {r.choice(_SAY).lower()} the {r.choice(_WORDS)} ends {r.choice(_TIMES)}.",
    lambda r: f"Our teacher called the {r.choice(_WORDS)} \"{r.choice(_QUOTED)}\" / \"{r.choice(_QUOTED)}\" depending on the day; whatever, we'll see.",
    lambda r: f"{r.choice(_SAY)} it's already {r.choice(_TIMES)}... the {r.choice(_WORDS)} doesn't wait, does it?",
    lambda r: f"The frame measures {r.randint(4, 9)}'{r.randint(0, 11)}\" tall -- {r.choice(_SAY).lower()} the {r.choice(_WORDS)} fits.",
    lambda r: f"Teachers hate '{r.choice(_QUOTED)}' in essays -- it's vague; write about the {r.choice(_WORDS)} instead.",
    lambda r: f"Text from Sam: 'running late -- {r.choice(_TIMES)} works?' Reply: 'yep, the {r.choice(_WORDS)} can wait.'",
    lambda r: f"Heads up: the '{r.choice(_QUOTED)}' option is off by default -- ask before the {r.choice(_WORDS)}!",
    lambda r: f"{r.choice(_NAMES)}'s {r.choice(_WORDS)}: \"{r.choice(_QUOTED)}\" -- {r.choice(_TIMES)}; bring snacks & water.",
    lambda r: f"Everyone misses a {r.choice(_WORDS)} once -- it's fine; we'll try again {r.choice(_TIMES)} (promise).",
]


def generate(n: int = 12000, seed: int = 1) -> list[tuple[str, int]]:
    """(text, template_id) pairs, unique texts, templates drawn at random."""
    r, seen, out = random.Random(seed), set(), []
    for _ in range(n * 3):
        if len(out) >= n:
            break
        tid = r.randrange(len(_T))
        t = _T[tid](r)
        if t not in seen:
            seen.add(t)
            out.append((t, tid))
    return out
