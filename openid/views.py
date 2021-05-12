from formshare.plugins.utilities import FormSharePublicView, FormSharePrivateView


class MyPublicView(FormSharePublicView):
    def process_view(self):
        return {}


class MyPrivateView(FormSharePrivateView):
    def process_view(self):
        self.set_active_menu("myCustomMenu")
        self.showWelcome = True
        return {"message": self._("Just a message from the plugin")}
