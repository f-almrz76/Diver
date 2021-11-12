from flask import Flask, request, jsonify, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
import pymssql
from flask_jwt_extended import get_jwt_identity, jwt_required, create_access_token, JWTManager

app = Flask(__name__)

app.config['SECRET_KEY'] = 'fateme9512399586'
app.config['JWT_SECRET_KEY'] = "@-@_@sfao@npn$Inp][][][gpsd"
jwt = JWTManager(app)


def connection_db():
    if "conn" not in g:
        g.conn = pymssql.connect(server="DESKTOP-6KQ3VDR", database="diver")
    return g.conn


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
    # gets phone and password
    phone = data.get('phone')
    password = data.get('password')
    # checking for existing user
    connection = connection_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Users WHERE phone= %s", phone)
    user = cursor.fetchone()
    if not user:
        cursor.execute(
            "INSERT INTO Users(phone,password) VALUES (%d, %s) ",
            (phone, generate_password_hash(password,method='sha256'))
        )
        connection.commit()
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
    if not auth or not auth.get('phone') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )
    connection = connection_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Users WHERE phone= %s", auth.get('phone'))
    user = cursor.fetchone()

    if user is None:
        # returns 401 if user does not exist
        return make_response(
            "User does not exist !!",
            401
        )

    if check_password_hash(user[1], auth.get('password')):
        access_token = create_access_token(identity=user[0])
        return make_response(jsonify({'token': access_token}), 201)
    # returns 403 if password is wrong
    return make_response(
        "Wrong Password !!",
        403,
    )


# User Database Route
# this route sends back list of users users
@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    output = []
    connection = connection_db()
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM Users')
    for row in cursor:
        output.append({
            'phone': row[0],
            'username': row[2],
        })
    return jsonify({'users': output})


@app.route('/update', methods=['PUT'])
@jwt_required()
def update():
    connection = connection_db()
    cursor = connection.cursor()
    current_user = get_jwt_identity()
    data = request.form
    username = data.get('username')
    cursor.execute("UPDATE Users set username=%s WHERE phone=%s", (username, current_user))
    connection.commit()
    return jsonify(msg="updated successfully."), 200


if __name__ == "__main__":
    app.run(debug=True)
