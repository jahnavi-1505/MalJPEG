from flask import Flask, jsonify, render_template, request
import os
import pickle

uploaded_metadata = {}

save_path = r'C:\Users\shrey\Documents\malware_png_detector.pkl'
vect_path = r'C:\Users\shrey\OneDrive\Documents\dict_vectorizer.pkl'

with open(save_path, 'rb') as f:
    loaded_model = pickle.load(f)

with open(vect_path, 'rb') as f:
    loaded_vectorizer = pickle.load(f)

from IS_traditional_PNG_detection import is_png, extract_features, check_chunks, check_png_for_large_idat, check_metadata

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    global uploaded_metadata
    if 'file' not in request.files:
        return "Error: No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "Error: No selected file", 400

    if file and file.filename.lower().endswith('.png'):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        if(is_png(file_path) == False):
            return "Please upload file with PNG format.", 415

        check_metadata(file_path)
        chunk_check, chunk_frequency = check_chunks(file_path)
        size_check, validity = check_png_for_large_idat(file_path)

        uploaded_metadata = str(chunk_frequency)

        if(size_check == "Suspicious PNG detected"):
            size1 = 1
        else:
            size1 = 0

        if(chunk_check == "PNG has passed chunk validation."):
            chunk1 = 0
        else:
            chunk1 = 1

        new_features = []
        new_features.append(extract_features(file_path))

        new_X = loaded_vectorizer.transform(new_features)
        prediction = loaded_model.predict(new_X)
        print("Prediction (0 = benign, 1 = malicious):", prediction)

        if(prediction[0] == 0 and validity == 0):
        # message displaying result of analysis
            result_message = chunk_check + size_check + "File is safe to upload."
        elif(prediction[0] == 0):
            result_message = "Model classifies file to be benign; " + chunk_check
        else:
            if chunk1 == 1 and size1 == 1:
                result_message = "Warning: Potential Malware. \n" + chunk_check + "\n" + size_check
            elif size1 == 1:
                result_message = "Warning: Potential Malware\n" + size_check
            else:
                result_message = chunk_check + "\tFile is safe to upload."

        return result_message, 200

    else:
        return "File format not supported.", 415

@app.route('/metadata', methods=['GET'])
def get_metadata():
    global uploaded_metadata
    return jsonify(uploaded_metadata), 200


if __name__ == '__main__':
    app.run(debug=True)
