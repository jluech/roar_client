import configparser
import os


CONFIG_FILE_PATH = "config.file"
RESET_FILE_PATH = "reset.marker"
TERMINATE_FILE_PATH = "terminate.marker"


def get_config_path():
    return CONFIG_FILE_PATH


def get_reset_path():
    return RESET_FILE_PATH


def get_terminate_path():
    return TERMINATE_FILE_PATH


def update_existing_config(new_config):
    if not os.path.exists(CONFIG_FILE_PATH):
        with open(CONFIG_FILE_PATH, "x"):
            pass
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE_PATH)
        config.add_section("GENERAL")
        config.add_section("BURST")
    else:
        config = get_config_from_file()
    config.set("GENERAL", "algo", new_config["algo"])
    config.set("GENERAL", "rate", new_config["rate"])
    config.set("BURST", "duration", new_config["burst_duration"])
    config.set("BURST", "pause", new_config["burst_pause"])

    with open(os.path.join(os.path.curdir, CONFIG_FILE_PATH), "w") as config_file:
        config.write(config_file)


def get_config_from_file():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE_PATH)
    return config
