import os
import sys
import jwt
import uuid
import datetime
from auth import encode_auth_token, decode_auth_token
from flask import Flask, request, abort, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from models import setup_db, Question, Answer, User, db, BlacklistToken
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import werkzeug.exceptions as ex


app = Flask(__name__)

app.config.from_object('config.ProductionConfig')
setup_db(app, app.config.get('SQLALCHEMY_DATABASE_URI'))


QUESTIONS_PER_PAGE = 10

def authRequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        auth_header = request.headers.get('Authorization')
        if auth_header:
            
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'success': False,
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        

        if auth_token:
            resp = decode_auth_token(app.config.get('SECRET_KEY'), auth_token)
            if not isinstance(resp, str):
                current_user = User.query.filter_by(id=resp).first()
            else:
                responseObject = {
                'success': False,
                'message': resp
            }   
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'success': False,
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

        return f(current_user, *args, **kwargs)

    return decorated


def getQuestionByIDHELPER(question_id):
    question = Question.query.get(question_id)
    if question is None:
        abort(404)

    return question


def getAnswerByIDHELPER(answer_id):
    answer = Answer.query.get(answer_id)
    if answer is None:
        abort(404)

    return answer


def getUserByIDHELPER(user_id):
    user = User.query.get(user_id)
    if user is None:
        abort(404)

    return user


def paginateGeneral(request, entity):
    page = request.args.get('page', 1, type=int)
    selection = entity.query.order_by(
        entity.id).paginate(page, QUESTIONS_PER_PAGE)
    return selection


@app.route('/')
def hello():
    return 'Welcome to our API'


@app.route('/questions', methods=['GET'])
def getAllQuestions():
    currentQuestions = paginateGeneral(request, Question)
    finalRes = [m.format() for m in currentQuestions.items]
    if len(finalRes) == 0:
        abort(404)

    return jsonify({
        'success': True,
        'questions': finalRes
    })

# Add question.
@app.route('/questions', methods=['POST'])
@authRequired
def addQuestion(current_user):
    body = request.get_json()
    
    try:
        questionTitle = body.get('title')
        questionContent = body.get('content')
        authorId = current_user.id
        if (questionTitle is None) or (questionContent is None) or (authorId is None):
            abort(400)

        question = Question(title=questionTitle,
                            content=questionContent, uid=authorId)
        question.insert()

        return jsonify({
            "success": True,
            "question": question.format()
        })
    except:
        abort(500)

@app.route('/questions/search', methods=['POST'])
def searchQuestions():
    body = request.get_json()
    search = body.get('search', None)

    try:
        if search:
            selection = Question.query.filter(
            Question.title.ilike("%{}%".format(search))).all()
        if not selection:
            abort(404)
        currentQuestions = [q.format() for q in selection]
        return jsonify({
            'success': True,
            'questions': currentQuestions

        })
    except:
        abort(500)

@app.route('/questions', methods=['PUT', 'DELETE'])
def noAccessToQuestionsDeletetionAndAltering():
    abort(405)


# On getting question by ID -> Question, Author, Answers ..
@app.route('/questions/<int:question_id>', methods=['GET'])
def getQuestionByID(question_id):
    question = getQuestionByIDHELPER(question_id)
    author = getUserByIDHELPER(question.uid)
    answers = Answer.query.filter(Answer.qid == question_id).all()
    answersOfQuestion = []

    for item in answers:
        answersOfQuestion.append({
            'content': item.content,
            'author_id': item.uid
        })

    if question is None:
        abort(404)

    return jsonify({
        'success': True,
        'question': question.format(),
        'author': {
            'first_name': author.first_name,
            'last_name': author.last_name
        },
        'answers': answersOfQuestion
    })


@app.route('/questions/<int:question_id>', methods=['DELETE', 'POST', 'PATCH'])
def deleteQuestion(question_id):
    abort(405)



@app.route('/questions/<int:question_id>/answers', methods=['PUT', 'DELETE', 'PATCH'])
def noAccess(question_id):
    abort(405)


@app.route('/questions/<int:question_id>/answers', methods=['GET'])
def getAnswersOfAQuestion(question_id):
    answers = Answer.query.filter(Answer.qid == question_id).all()
    finalRes = []
    for item in answers:
        answerAuthor = getUserByIDHELPER(item.uid)
        finalRes.append({
            'content': item.content,
            'author': {
                'first_name': answerAuthor.first_name,
                'last_name': answerAuthor.last_name
            }
        })
    return jsonify({
        'success': True,
        'answers': finalRes
    })


# Needs Login
@app.route('/questions/<int:question_id>/answers', methods=['POST'])
@authRequired
def addAnswersOfAQuestion(current_user, question_id):
    body = request.get_json()
    try:
        answerContent = body.get('content')
        authorId = current_user.id
        if (answerContent is None) or (authorId is None):
            abort(400)

        answer = Answer(content=answerContent, uid=authorId, qid=question_id)
        answer.insert()

        return jsonify({
            "success": True,
            "answer": answer.format()
        })
    except:
        abort(422)


@app.route('/users/login', methods=['POST'])
def loginUser():
    # get the post data
    post_data = request.get_json()
    
    try:
        # fetch the user data
        user = User.query.filter_by(
            email=post_data.get('email')
        ).first()
        if user and check_password_hash(
            user.password, post_data.get('password')
        ):
            
            auth_token = encode_auth_token(
                app.config.get('SECRET_KEY'), user.id)
            print(auth_token)
            if auth_token:
                responseObject = {
                    'success': True,
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token.decode('UTF-8')
                }
                return make_response(jsonify(responseObject)), 200
        else:
            abort(404)
    except:
        abort(500)


@app.route('/users/signup', methods=['POST'])
def signup():
    body = request.get_json()
    # check if user already exists
    user = User.query.filter_by(email=body.get('email')).first()
    if not user:
        
        userFirstName = body.get('first_name')
        userLastName = body.get('last_name')
        userEmail = body.get('email')
        if (userFirstName is None) or (userLastName is None) or (userEmail is None):
            abort(400)

        userPassword = generate_password_hash(
            body.get('password'), method='sha256')

        user = User(first_name=userFirstName, last_name=userLastName,
                    email=userEmail, password=userPassword)
        user.insert()
        # generate the auth token
        auth_token = encode_auth_token(
            app.config.get('SECRET_KEY'), user.id)
        return jsonify({
            'success': True,
            'message': 'User has been created',
            'authToken': auth_token.decode('UTF-8')
        })
       
    else:
        responseObject = {
                'success': False,
                'message': 'User already exists. Please Log in.',
            }
        return make_response(jsonify(responseObject)), 401


@app.route('/users/logout', methods=['POST'])
def logoutUser():
    # get auth token
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = decode_auth_token(app.config.get('SECRET_KEY'), auth_token)
        if not isinstance(resp, str):
            # mark the token as blacklisted
            blacklist_token = BlacklistToken(token=auth_token)
            try:
                # insert the token
                blacklist_token.insert()
                responseObject = {
                    'success': True,
                    'message': 'Successfully logged out.'
                }
                return make_response(jsonify(responseObject)), 200
            except Exception as e:
                responseObject = {
                    'success': False,
                    'message': e
                }
                return make_response(jsonify(responseObject)), 200
        else:
            responseObject = {
                'success': False,
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'success': False,
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), 403

# Needs Login


@app.route('/users/<int:user_id>/questions', methods=['GET'])
@authRequired
def getUserQuestions(current_user, user_id):
    if current_user.id == user_id:
        try:
            questions = Question.query.filter(Question.uid == user_id).all()
            finalRes = [q.format() for q in questions]
            return jsonify({
                'success': True,
                'questions': finalRes
            })
        except:
            abort(500)
    else:
        abort(401)

@app.route('/users/<int:user_id>/answers', methods=['GET'])
@authRequired
def getUserAnswers(current_user, user_id):
    if current_user.id == user_id:
        try:
            answers = Answer.query.filter(Question.uid == user_id).all()
            finalRes = [a.format() for a in answers]
            return jsonify({
                'success': True,
                'questions': finalRes
            })
        except:
            abort(500)
    else:
        abort(401)


# Error Handling
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": 'Unauthorized'
    }), 401




@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": 'Internal Server Error'
    }), 500


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": 'Bad Request'
    }), 400


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": 'Method Not Allowed'
    }), 405


if __name__ == '__main__':
    app.run()
