import configparser
import os


def update_existing_config(new_config):
    config = get_config_from_file()
    config.set("ALGORITHM", "algo", new_config["algo"])
    config.set("BURST", "duration", new_config["burst_duration"])
    config.set("BURST", "pause", new_config["burst_pause"])
    config.set("BURST", "rate", new_config["burst_rate"])

    with open(os.path.join(os.path.curdir, "./config.file"), "w") as config_file:
        config.write(config_file)


def get_config_from_file():
    config = configparser.ConfigParser()
    config.read("config.file")
    return config
