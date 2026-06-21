"""Check registry. Checks register themselves via the @register decorator."""


class CheckSpec(object):
    def __init__(self, id, title, category, func, order=100):
        self.id = id
        self.title = title
        self.category = category
        self.func = func
        self.order = order


REGISTRY = []


def register(id, title, category, order=100):
    """Decorate a generator/function that yields Finding objects."""
    def deco(func):
        REGISTRY.append(CheckSpec(id, title, category, func, order))
        return func
    return deco


def all_checks():
    # Keep categories contiguous in first-registration order, then sort by
    # each check's `order` within its category.
    cat_index = {}
    for spec in REGISTRY:
        if spec.category not in cat_index:
            cat_index[spec.category] = len(cat_index)
    return sorted(REGISTRY, key=lambda c: (cat_index[c.category], c.order, c.id))


def categories():
    seen = []
    for c in all_checks():
        if c.category not in seen:
            seen.append(c.category)
    return seen
