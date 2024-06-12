from configparser import ConfigParser


class Config:
    def __init__(self):
        try:
            self.config_object = ConfigParser()
            self.config_object.read("Config/config.ini")
        except Exception as e:
            print(e)