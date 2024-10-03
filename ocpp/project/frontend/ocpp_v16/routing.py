import functools

routables = []


def on(action, *, skip_schema_validation=False):

    def decorator(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            return func(*args, **kwargs)

        inner._on_action = action
        inner._skip_schema_validation = skip_schema_validation
        if func.__name__ not in routables:
            routables.append(func.__name__)
        return inner

    return decorator


def after(action):

    def decorator(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            return func(*args, **kwargs)

        inner._after_action = action
        if func.__name__ not in routables:
            routables.append(func.__name__)
        return inner

    return decorator


def create_route_map(obj):

    routes = {}
    for attr_name in routables:
        for option in ["_on_action", "_after_action"]:
            try:
                attr = getattr(obj, attr_name)
                action = getattr(attr, option)

                if action not in routes:
                    routes[action] = {}

                if option == "_on_action":
                    routes[action]["_skip_schema_validation"] = getattr(
                        attr, "_skip_schema_validation", False
                    )

                routes[action][option] = attr

            except AttributeError:
                continue

    return routes
