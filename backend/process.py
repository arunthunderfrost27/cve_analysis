from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson import json_util
import json

app = Flask(__name__)
CORS(app)

MONGO_URI = "mongodb+srv://arunbalsen27:cvedatabase@cluster0.gteym.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
HOMEPAGE_TEMPLATE = Path('E:/CVE Analyser/frontend') / 'homepage.html'
DETAILPAGE_TEMPLATE = Path('E:/CVE Analyser/frontend') / 'detailpage.html'


def get_mongo_client():
    try:
        client = MongoClient(MONGO_URI)
        client.admin.command('ping')
        return client
    except Exception as e:
        print(f"MongoDB connection error: {e}")
        return None


def json_response(data):
    return json.loads(json_util.dumps(data))


@app.route('/')
def homepage():
    if not HOMEPAGE_TEMPLATE.exists():
        return "Homepage template not found", 404
    return render_template(HOMEPAGE_TEMPLATE.name)


@app.route('/cves/list')
def cves_list_page():
    if not HOMEPAGE_TEMPLATE.exists():
        return "Homepage template not found", 404
    return render_template(HOMEPAGE_TEMPLATE.name)


@app.route('/cves/<cve_id>')
def cve_detail_page(cve_id):
    if not DETAILPAGE_TEMPLATE.exists():
        return "Detail page template not found", 404
    return render_template(DETAILPAGE_TEMPLATE.name)


@app.route('/api/cves', methods=['GET'])
def get_cve_list():
    client = get_mongo_client()
    if not client:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        db = client['cluster0']
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit

        metadata_collection = db['cve_metadata']
        total_records = metadata_collection.count_documents({})

        cves = list(metadata_collection.find({})
                    .skip(skip)
                    .limit(limit)
                    .sort('published', -1))

        return jsonify({
            "total": total_records,
            "cves": json_response(cves)
        })
    except Exception as e:
        print(f"Error fetching CVE list: {e}")
        return jsonify({"error": "Failed to retrieve CVE list"}), 500
    finally:
        client.close()


@app.route('/api/cves/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    client = get_mongo_client()
    if not client:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        db = client['cluster0']

        metadata = db['cve_metadata'].find_one({"cve_id": cve_id})

        descriptions = db['descriptions'].find_one({"cve_id": cve_id})

        metrics = list(db['metrics'].find({"cve_id": cve_id}))

        cpe = list(db['cpe'].find({"cve_id": cve_id}))

        cve_details = {
            "cve_id": cve_id,
            "metadata": json_response(metadata),
            "descriptions": json_response(descriptions)['descriptions'] if descriptions else [],
            "metrics": json_response(metrics),
            "cpe": json_response(cpe)
        }

        return jsonify(cve_details)
    except Exception as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
        return jsonify({"error": f"Failed to retrieve details for CVE {cve_id}"}), 500
    finally:
        client.close()


if __name__ == '__main__':
    app.template_folder = str('E:/CVE Analyser/frontend')
    app.run(debug=True, host='0.0.0.0', port=5000)
