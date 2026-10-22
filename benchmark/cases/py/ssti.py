from flask import request, render_template_string


def greet():
    name = request.args.get("name")
    return render_template_string("hello " + name)
