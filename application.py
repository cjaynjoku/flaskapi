from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

application = Flask(__name__)


application.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://john:password@localhost/pets'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(application)


class Pet(db.Model):
    __tablename__ = 'pets'
    id = db.Column(db.Integer, primary_key = True)
    pet_name = db. Column(db.String(100), nullable = False)
    pet_type = db.Column(db.String(100), nullable = False)
    pet_age = db.Column(db.Integer(), nullable = False)
    pet_description = db.Column(db.String(100), nullable = False)

    def __repr__(self):
        return "<Pet %r>" % self.pet_name



db.create_all()

# The @application.route decorator is used to handle requests, and to define a function "index" that
# is used to return a jsonified message
@application.route('/')
def index():
    return jsonify({"message":"Welcome to my site"})


#POST ENDPOINT
@application.route('/pets', methods=['POST'])
def create_pet():
    pet_data = request.json

    pet_name = pet_data['pet_name']
    pet_type = pet_data['pet_type']
    pet_age = pet_data['pet_age']
    pet_description = pet_data['pet_description']


    pet = Pet(pet_name=pet_name, pet_type=pet_type, pet_age=pet_age, pet_description=pet_description)
    db.session.add(pet)
    db.session.commit()

    return jsonify({"success": True, "response": "Pet added"})


# Using the GET method to return all entries
@application.route("/getpets", methods =['GET'])
def get_pets():
    all_pets =[]
    pets = Pet.query.all()
    for pet in pets:
        results = {
            "pet_id":pet.id,
            "pet_name":pet.pet_name,
            "pet_age":pet.pet_age,
            "pet_type":pet.pet_type,
            "pet_description":pet.pet_description,
        }

        all_pets.applicationend(results)
    return jsonify(
        {
             "success": True,
             "pets": all_pets,
             "total_pets": len(pets)
                     }
    )


# Using the patch endpoint to update the details of a pet
@application.route("/pets/<int:pet_id>", methods=["PATCH"])
def update_pet(pet_id):
    pet = Pet.query.get(pet_id)
    pet_age = request.json['pet_age']
    pet_description = request.json['pet_description']
    pet_name = request.json['pet_name']

    if pet is None:
        abort(404)
    else:
        pet.pet_age = pet_age
        pet.pet_description = pet_description
        pet.pet_name = pet_name
        db.session.add(pet)
        db.session.commit()
        return jsonify({
            "success":True,
            "response": "Pet details updated"
        })


# Using the Delete method to delete a pet from the database
@application.route("/pets/<id>", methods=['DELETE'])
def pet_delete(id):
    pet = Pet.query.get(id)
    db.session.delete(pet)
    db.session.commit()

    return jsonify({
        "success":True,
        "response":"Record successfully deleted"
    })

if __name__ == '__main__':
  application.run(debug=True)