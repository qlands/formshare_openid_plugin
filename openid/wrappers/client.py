from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError


class ClientWrapper(object):
    """
    This class is a Wrapper to pull and push clients from/to the table openidclients in MySQL
    """

    def __init__(self, db_uri):
        self._db_uri = db_uri

    def __setitem__(self, key, value):
        engine = create_engine(self._db_uri)
        try:
            engine.execute(
                "INSERT INTO openidclients (client_id,client_name,application_type,"
                "redirect_uris,client_id_issued_at,client_secret,"
                "client_secret_expires_at,response_types) VALUES ('{}','{}','{}','{}',{},'{}',{},'{}')".format(
                    value.get("client_id"),
                    value.get("client_name"),
                    value.get("application_type"),
                    "|~|".join(value.get("redirect_uris")),
                    value.get("client_id_issued_at"),
                    value.get("client_secret"),
                    value.get("client_secret_expires_at"),
                    "|~|".join(value.get("response_types")),
                )
            )
        except IntegrityError:
            engine.execute(
                "UPDATE openidclients SET client_name = '{}', application_type = '{}',"
                "redirect_uris = '{}', client_id_issued_at = {}, client_secret = '{}',"
                "client_secret_expires_at = {}, response_types = '{}' WHERE client_id = '{}'".format(
                    value.get("client_name"),
                    value.get("application_type"),
                    "|~|".join(value.get("redirect_uris")),
                    value.get("client_id_issued_at"),
                    value.get("client_secret"),
                    value.get("client_secret_expires_at"),
                    "|~|".join(value.get("response_types")),
                    value.get("client_id"),
                )
            )
        engine.dispose()

    def __getitem__(self, key):
        engine = create_engine(self._db_uri)
        user = engine.execute(
            "SELECT client_name,application_type,redirect_uris,client_id_issued_at,"
            "client_secret,client_secret_expires_at,response_types FROM openidclients WHERE client_id = '{}'".format(
                key
            )
        ).fetchone()
        if user is not None:
            res = {
                "client_id": key,
                "client_name": user[0],
                "application_type": user[1],
                "redirect_uris": user[2].split("|~|"),
                "client_id_issued_at": user[3],
                "client_secret": user[4],
                "client_secret_expires_at": user[5],
                "response_types": user[6].split("|~|"),
            }
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
            "SELECT count(client_id) FROM openidclients WHERE client_id = '{}'".format(
                key
            )
        ).fetchone()
        count = user[0]
        engine.dispose()
        return bool(count)

    def items(self):
        engine = create_engine(self._db_uri)
        users = engine.execute(
            "SELECT client_id,client_name,application_type,redirect_uris,client_id_issued_at,"
            "client_secret,client_secret_expires_at,response_types FROM openidclients "
        ).fetchall()
        for user in users:
            yield user[0], {
                "client_id": user[0],
                "client_name": user[1],
                "application_type": user[2],
                "redirect_uris": user[3].split("|~|"),
                "client_id_issued_at": user[4],
                "client_secret": user[5],
                "client_secret_expires_at": user[6],
                "response_types": user[7].split("|~|"),
            }

    def pop(self, key, default=None):
        pass
