from flask import redirect, render_template, request, session
from functools import wraps
import string
import random
import pyowm

# Creates a string of 16 random characters
def random_generator():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for x in range(16))

# Turns an SQL-Alchemy query into a list of dictionaries in order to be sent in json format through the Flask's jsonify function
def turn_into_dictionary(results):
    final_list = []
    for result in results:
        obj = {
            "id" : result.id,
            "task" : result.task,
            "done" : result.done
        }
        final_list.append(obj)
    return final_list

# This communicates with the OpenWeather API in order to get the weather from the users location, returns a dictionary with all the necesary data
def weather(lat, lng):
    lat = float(lat)
    lng = float(lng)
    API_key = "0bc29b9bac5ae014e8d680d32b65322f"
    owm = pyowm.OWM(API_key)
    observation = owm.weather_at_coords(lat, lng)
    w = observation.get_weather()
    temperature = w.get_temperature(unit="celsius")
    dictionary ={
        "status" : (w.get_detailed_status()).capitalize(),
        "status_icon" : w.get_weather_icon_url(),
        "min_tmp" : temperature.get("temp_min"),
        "max_tmp" : temperature.get("temp_max"),
        "tmp" : temperature.get("temp"),
        "wind" : w.get_wind(),
        "humidity" : w.get_humidity()
    }
    return dictionary