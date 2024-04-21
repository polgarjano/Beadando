import pandas as pd

import json
from jsonschema import validate, ValidationError
import plotly.express as px

schema = ""

with open('./json/statisticInterface.json', 'r') as file:
    lines = file.readlines()
    schema = "".join(lines)
    schema = json.loads(schema)

print(schema)


def is_valid(json_str):
    try:
        # Parse the JSON string
        json_data = json.loads(json_str)
        # Validate against the schema
        validate(instance=json_data, schema=schema)
        return True
    except (ValidationError, json.JSONDecodeError):
        return False


def draw_scater(title, x, y):
    data = {
        "x": x,
        "y": y}

    df = pd.DataFrame(data)

    # Create a scatter plot
    fig = px.scatter(df, x='x', y='y', title=title)

    # Display the plot
    fig.show()


def draw(json_string):
    if not is_valid(json_string):
        draw_scater("ERROR", [], [])
        return

    json_data = json.loads(json_string)
    df = pd.DataFrame(json_data['values'])
    fig = px.line(df, x='x', y='y', color='classifier', markers=True, title=json_data['Title'])
    fig.show()


def readFromFile(path):
    example = ""
    with open(path, 'r') as file:
        example = file.readlines()
        example = " ".join(example)

    return example


if __name__ == '__main__':
    print("hello")
    print(True == is_valid(readFromFile('./json/example1.json')))
    print(False == is_valid(readFromFile('./json/example2.json')))
    draw(readFromFile('./json/example_date.json'))
    draw(readFromFile('./json/example2.json'))
