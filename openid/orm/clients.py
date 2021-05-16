class OpenIDClients(object):
    """
    ORM Class representing the table openidclients
    """

    def __init__(
        self,
        client_id,
        client_name,
        application_type,
        redirect_uris,
        client_id_issued_at,
        client_secret,
        client_secret_expires_at,
        response_types,
    ):
        self.client_id = client_id
        self.client_name = client_name
        self.application_type = application_type
        self.redirect_uris = redirect_uris
        self.client_id_issued_at = client_id_issued_at
        self.client_secret = client_secret
        self.client_secret_expires_at = client_secret_expires_at
        self.response_types = response_types
