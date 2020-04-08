
from flask_restx import fields, marshal
import fnmatch
import re

class MyWildcard(fields.Wildcard):
    """
    Customised Superclassed Wildcard field

    :param cls_or_instance: The field type the list will contain.
    """

    def output(self, key, obj, ordered=False):
        value = None
        reg = fnmatch.translate(key)

        if self._flatten(obj):
            while True:
                try:
                    # we are using pop() so that we don't
                    # loop over the whole object every time dropping the
                    # complexity to O(n)
                    (objkey, val) = self._flat.pop()
                    if (
                        objkey not in self._cache
                        and objkey not in self.exclude
                        ## changed to str(objkey)
                        and re.match(reg, str(objkey), re.IGNORECASE)
                    ):
                        value = val
                        self._cache.add(objkey)
                        self._last = objkey
                        break
                except IndexError:
                    break

        if value is None:
            if self.default is not None:
                return self.container.format(self.default)
            return None

        # changed to fields.Nested
        if isinstance(self.container, fields.Nested):
            return marshal(
                value,
                self.container.nested,
                skip_none=self.container.skip_none,
                ordered=ordered,
            )
        return self.container.format(value)
