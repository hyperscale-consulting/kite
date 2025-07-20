from typing import Any


def get_name_from_tag(resource: dict[str, Any], default="") -> str:
    tags = resource.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", default)
    return default
