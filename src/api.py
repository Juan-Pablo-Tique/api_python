from flask import Flask, jsonify, request, json, Response
from flask_pymongo import PyMongo
from bson import ObjectId, json_util
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://admin_001:admin_001#@clustervote-01yna.gcp.mongodb.net/ClusterVote?retryWrites=true&w=majority'
app.config['JWT_SECRET_KEY'] = 'secret123'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# lista de colecciones
db_leader = mongo.db.leader
db_role = mongo.db.role
db_leader = mongo.db.leader
db_department = mongo.db.department
db_voter = mongo.db.voter_information
db_neighborhood = mongo.db.neighborhood
db_voting_station = mongo.db.voting_station
db_log = mongo.db.log


@app.route('/', methods=['GET'])
@jwt_required
def get():
    uid = (get_jwt_identity())['id']
    print(uid)
    return jsonify({'rol':'rol'}), 200


@app.route('/login', methods=['POST'])
def login():

    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ''

    response = db_leader.find_one({'email': email})

    if response:
        if bcrypt.check_password_hash(response['password'], password):

            # id de administrador o lider
            role = (db_role.find_one({'_id': response['role']}))['role']

            access_token = create_access_token(identity={
                'role': role,
                'id': str(response['_id'])
            })
            result = jsonify({'token': access_token})
        else:
            result = jsonify({'error': 'Invalid password'})
    else:
        result = jsonify({'error': 'Invalid email'})

    return result


@app.route('/create/leader', methods=['POST'])
@jwt_required
def create_leader():
    if (get_jwt_identity())['role'] == 'Administrador':

        leader_role = (db_role.find_one({'role': 'Lider'}))['_id'] #se busca el id de lider

        names = request.get_json()['names']
        surnames = request.get_json()['surnames']
        city = request.get_json()['city']
        address = request.get_json()['address']
        cellphone = request.get_json()['cellphone']
        email = request.get_json()['email']
        password = bcrypt.generate_password_hash(
            request.get_json()['password']).decode('utf-8')
        role = ObjectId(leader_role)
        created = datetime.now()

        leader_id = db_leader.insert({
            'names': names,
            'surnames': surnames,
            'city': city,
            'address': address,
            'cellphone': cellphone,
            'email': email,
            'password': password,
            'role': role,
            'created': created
        })

        new_leader = db_leader.find_one({'_id': leader_id})
        result = {'email': new_leader['email']}

        return jsonify({'result': result})
    else:
        return role_administrator()

# voter (votante)
@app.route('/create/voter', methods=['POST'])
@jwt_required
def create_voter():
    if (get_jwt_identity())['role'] == 'Lider':

        names = request.get_json()['names']
        surnames = request.get_json()['surnames']
        city = request.get_json()['city']
        address = request.get_json()['address']
        cellphone = request.get_json()['cellphone']
        document = request.get_json()['document']
        table = request.get_json()['table']
        neighborhood = ObjectId(request.get_json()['neighborhood'])
        voting_station = ObjectId(request.get_json()['voting_station'])

        leader = ObjectId((get_jwt_identity())['id'])
        created = datetime.now()

        if names and surnames and city and address and cellphone and document and leader and neighborhood and voting_station and table and created:
            neighborhood_id = db_neighborhood.find_one({'_id': neighborhood})
            
            if neighborhood_id:
                voting_station_id = db_voting_station.find_one({'_id': voting_station})

                if voting_station_id:
                    db_voter.insert({
                        'names': names,
                        'surnames': surnames,
                        'city': city,
                        'address': address,
                        'cellphone': cellphone,
                        'document': document,
                        'leader': leader,
                        'neighborhood': neighborhood,
                        'voting_station': voting_station,
                        'table': table,
                        'created': created
                    })

                    # se crea una copia en la coleccion log solo el administrador podra visulizarla
                    db_log.insert({
                        'names': names,
                        'surnames': surnames,
                        'city': city,
                        'address': address,
                        'cellphone': cellphone,
                        'document': document,
                        'leader': leader,
                        'neighborhood': neighborhood,
                        'voting_station': voting_station,
                        'table': table,
                        'created': created
                    })

                    return insert_ok()
                else:
                    return failed(voting_station, 'voting_station')
            else:
                return failed(neighborhood, 'neighborhood')
        else:
            return incomplete_data()
    else:
        return role_leader()

        

# log
@app.route('/find/log/<id>', methods=['GET'])
@jwt_required
def find_log(id):
    if (get_jwt_identity())['role'] == 'Administrador':
        if request.method == 'GET':
            find_log = db_log.find_one({'_id': ObjectId(id)})

            find_log_count = find_log.count()

            find_log_str = json_util.dumps(find_log)

            if find_log_count > 0:
                return Response(find_log_str, mimetype='application/json'), 200

            else:
                return no_data('log')
        else:
            return incomplete_data()
    else:
        return role_administrator()



# department (departamentos)
@app.route('/create/department', methods=['POST'])
@jwt_required
def create_department():
    name = request.get_json()['name']
    status = 'Activo'

    if name and request.method == 'POST':
        find_department = db_department.find_one({'name': name})

        if not find_department:
            db_department.insert_one({
                'name': name,
                'status': status
            })

            return insert_ok()

        else:
            return already_created(name, 'department')
    else:
        return incomplete_data()


@app.route('/find/departments', methods=['GET'])
@jwt_required
def find_departments():
    find_departments = db_department.find()

    find_departments_count = find_departments.count()

    find_departments_str = json_util.dumps(find_departments)

    if find_departments_count > 0:
        return Response(find_departments_str, mimetype='application/json'), 200

    else:
        return no_data('department')


@app.route('/find/department/<id>', methods=['GET'])
@jwt_required
def find_department(id):
    find_department = db_department.find_one({'_id': ObjectId(id)})

    find_department_str = json_util.dumps(find_department)

    if find_department:
        return Response(find_department_str, mimetype='application/json'), 200

    else:
        return no_data('department')


@app.route('/update/department/<id>', methods=['PUT'])
@jwt_required
def update_department(id):
    name = request.get_json()['name']
    status = request.get_json()['status']

    update_department_found = db_department.find_one({'name': name})

    if update_department_found:
        return already_created(name,'department')
    else:
        if name and status and request.method == 'PUT':
            update_department = db_department.find_one_and_update({'_id': ObjectId(id)}, {'$set': {
                'name': name,
                'status': status
            }})

            if update_department:
                return update_ok(id,'department')

            else:
                return failed(id,'department')
        else:
            return incomplete_data()



# funciones de mensajes
@app.errorhandler(404)
def not_found(error=None):
    response = jsonify({
        'message': 'Resource not found ' + request.url,
        'status': 404
    })

    response.status_code = 404

    return response

@app.errorhandler(405)
def method_not_allowed(error=None):
    response = jsonify({
        'message': 'Method not allowed',
        'status': 405
    })

    response.status_code = 405

    return response


def insert_ok():
    response = jsonify({
        'result': 'Created successfully',
        'status': 201
    })

    response.status_code = 201

    return response


def already_created(data_send=None, collection=None):
    response = jsonify({
        'result': data_send + ' ' + collection + ' is already created',
        'status': 400
    })

    response.status_code = 400

    return response


def incomplete_data():
    response = jsonify({
        'result': 'Incomplete data',
        'status': 400
    })

    response.status_code = 400

    return response

def no_data(collection=None):
    response = jsonify({
        'result': 'no data in ' + collection,
        'status': 400
    })

    response.status_code = 400

    return response

def update_ok(id=None, collection=None):
    response = jsonify({
        'result': collection + ' ' + id + ' was updated successfully',
        'status': 200
    })

    response.status_code = 200

    return response

def failed(id=None, collection=None):
    response = jsonify({
        'result': collection + ' ' + id + ' not found',
        'status': 400
    })

    response.status_code = 400

    return response

def role_administrator():
    response = jsonify({
        'result': 'You do not have the administrator role',
        'status': 401
    })

    response.status_code = 401

    return response

def role_leader():
    response = jsonify({
        'result': 'You do not have the leader role',
        'status': 401
    })

    response.status_code = 401

    return response

if __name__ == '__main__':
    app.run(debug=True)
