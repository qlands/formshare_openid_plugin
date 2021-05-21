from sqlalchemy import create_engine


class UserWrapper(object):
    """
    A wrapper class to pull users from FormShare
    """

    def __init__(self, db_uri):
        self._db_uri = db_uri

    def __setitem__(self, key, value):
        pass

    def __getitem__(self, key):
        engine = create_engine(self._db_uri)
        user = engine.execute(
            "SELECT user_name,user_email FROM fsuser WHERE user_id = '{}'".format(key)
        ).fetchone()
        if user is not None:
            res = {"name": key}
            engine.dispose()
            return res
        else:
            engine.dispose()
            raise KeyError(key)

    def __delitem__(self, key):
        pass

    def __contains__(self, key):
        engine = create_engine(self._db_uri)
        user = engine.execute(
            "SELECT user_name FROM fsuser WHERE user_id = '{}'".format(key)
        ).fetchone()
        engine.dispose()
        if user is None:
            return False
        else:
            return True

    def items(self):
        engine = create_engine(self._db_uri)
        users = engine.execute("SELECT user_id FROM fsuser").fetchall()
        users_dict = {}
        for a_user in users:
            yield users_dict[a_user[0]], {"name": a_user[0]}
        engine.dispose()

    def pop(self, key, default=None):
        pass
