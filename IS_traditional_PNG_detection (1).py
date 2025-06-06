from PIL import Image
import png
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import accuracy_score
import os

import struct
import zlib
import math

def is_png(file_path):
    """Check if a file is in PNG format by verifying the file signature."""
    png_signature = b'\x89PNG\r\n\x1a\n'
    try:
        with open(file_path, 'rb') as f:
            file_header = f.read(8)
            if file_header == png_signature:
                return True
            else:
                return False
    except Exception as e:
        print(f"Error reading file: {e}")
        return False

def calculate_entropy(data):
    """Calculate entropy of given data."""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    frequencies = {byte: data.count(byte) for byte in set(data)}
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def check_png_for_large_idat(file_path):
    total_idat_size = 0
    suspicious = False
    large_chunk_threshold = 65_000

    with open(file_path, 'rb') as f:
        # PNG signature
        signature = f.read(8)
        if signature != b'\x89PNG\r\n\x1a\n':
            print("Not a valid PNG file.")
            return "Not a valid PNG file"

        while True:
            chunk_header = f.read(8)
            if len(chunk_header) < 8:
                break

            chunk_length, chunk_type = struct.unpack('>I4s', chunk_header)
            chunk_data = f.read(chunk_length)
            chunk_crc = f.read(4)

            if chunk_type == b'IDAT':
                total_idat_size += chunk_length

                if chunk_length > large_chunk_threshold:
                    print(f"Large IDAT chunk detected: {chunk_length} bytes")
                    suspicious = True

                try:
                    decompressed_data = zlib.decompress(chunk_data)
                    entropy = calculate_entropy(decompressed_data)
                    print(f"IDAT chunk entropy: {entropy:.2f}")

                    if entropy > 7.5:
                        print("High entropy in IDAT chunk suggests hidden data.")
                        suspicious = True
                        
                except zlib.error:
                    print("Warning: Failed to decompress IDAT chunk. Possible corruption or malicious alteration.")
                    suspicious = True

            if chunk_type == b'IEND':
                break

    print(f"Total IDAT size: {total_idat_size} bytes")
    if suspicious:
        return "Suspicious PNG detected", 1
    else:
        return "Valid PNG", 0


benign_folder = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\Benign\Benign'
mal0 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Quakbot'
mal1 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\AgentTesla'
mal2 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Danabot'
mal3 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\CoinMinerXMRig'
mal4 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Formbook'
mal5 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Gh0stRAT'
mal6 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Glupteba'
mal7 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Gozi'
mal8 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Heodo'
mal9 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\NanoCore'
mal10 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\RecordBreaker'
mal11 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\RedLineStealer'
mal12 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Remcos'
mal13 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Tinba'
mal14 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Trickbot'
mal15 = r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Zeus'


benign_files = [os.path.join(benign_folder, f) for f in os.listdir(benign_folder) if f.endswith('.png')]
malicious_files = [os.path.join(mal0, f) for f in os.listdir(mal0) if f.endswith('.png')]
mal_1 = [os.path.join(mal1, f) for f in os.listdir(mal1) if f.endswith('.png')]
mal_2 = [os.path.join(mal2, f) for f in os.listdir(mal2) if f.endswith('.png')]
mal_3 = [os.path.join(mal3, f) for f in os.listdir(mal3) if f.endswith('.png')]
mal_4 = [os.path.join(mal4, f) for f in os.listdir(mal4) if f.endswith('.png')]
mal_5 = [os.path.join(mal5, f) for f in os.listdir(mal5) if f.endswith('.png')]
mal_6 = [os.path.join(mal6, f) for f in os.listdir(mal6) if f.endswith('.png')]
mal_7 = [os.path.join(mal7, f) for f in os.listdir(mal7) if f.endswith('.png')]
mal_8 = [os.path.join(mal8, f) for f in os.listdir(mal8) if f.endswith('.png')]
mal_9 = [os.path.join(mal9, f) for f in os.listdir(mal9) if f.endswith('.png')]
mal_10 = [os.path.join(mal10, f) for f in os.listdir(mal10) if f.endswith('.png')]
mal_11 = [os.path.join(mal11, f) for f in os.listdir(mal11) if f.endswith('.png')]
mal_12 = [os.path.join(mal12, f) for f in os.listdir(mal12) if f.endswith('.png')]
mal_13 = [os.path.join(mal13, f) for f in os.listdir(mal13) if f.endswith('.png')]
mal_14 = [os.path.join(mal14, f) for f in os.listdir(mal14) if f.endswith('.png')]
mal_15 = [os.path.join(mal15, f) for f in os.listdir(mal15) if f.endswith('.png')]


files = benign_files + malicious_files + mal_1 + mal_2 + mal_3 + mal_4 + mal_5 + mal_6 + mal_7 + mal_8 + mal_9 + mal_10 + mal_11 + mal_12 + mal_13 + mal_14 + mal_15
labels = [0] * len(benign_files) + [1] * (len(malicious_files) + len(mal_1) + len(mal_2) + len(mal_3) + len(mal_4) + len(mal_5) + len(mal_6) + len(mal_7) + len(mal_8) + len(mal_9) + len(mal_10) + len(mal_11) + len(mal_12) + len(mal_13) + len(mal_14) + len(mal_15))


def extract_features(file_path):
    features = {}
    try:
        with open(file_path, 'rb') as f:
            reader = png.Reader(f)
            chunks = list(reader.chunks())
            
            # total number of chunks and IDAT chunk count
            features['num_chunks'] = len(chunks)
            chunk_types = [chunk_type.decode('utf-8') for chunk_type, _ in chunks]
            features['num_IDAT'] = sum(1 for chunk_type in chunk_types if chunk_type == 'IDAT')
            
            # check for presence of text chunks
            text_chunks = [chunk_type for chunk_type in chunk_types if chunk_type in ['tEXt', 'zTXt', 'iTXt']]
            features['has_text'] = int(bool(text_chunks))
            
            # feature: total chunk length
            features['total_chunk_length'] = sum(len(chunk_data) for _, chunk_data in chunks)
            
            features['unusual_chunks'] = 0 
            
            total_idat_size = 0
            high_entropy_idat = 0
            large_idat_chunk_detected = 0
            large_chunk_threshold = 65_000
            
            for chunk_type, chunk_data in chunks:
                chunk_str = chunk_type.decode('utf-8')
                
                # large IDAT chunks check
                if chunk_str == 'IDAT':
                    chunk_length = len(chunk_data)
                    total_idat_size += chunk_length
                    if chunk_length > large_chunk_threshold:
                        large_idat_chunk_detected = 1
                    
                    # entropy for IDAT chunk
                    try:
                        decompressed_data = zlib.decompress(chunk_data)
                        entropy = calculate_entropy(decompressed_data)
                        if entropy > 7.5:  #  max entropy accepted
                            high_entropy_idat = 1
                    except zlib.error:
                        high_entropy_idat = 1  # suspicious if decompression fails
                        
            features['large_idat_chunk_detected'] = large_idat_chunk_detected
            features['high_entropy_idat'] = high_entropy_idat
            features['total_idat_size'] = total_idat_size

            # for text chunk metadata
            for chunk_type, chunk_data in chunks:
                if chunk_type.decode('utf-8') == 'tEXt':
                    try:
                        keyword, text = chunk_data.split(b'\x00', 1)
                        keyword = keyword.decode('utf-8')
                        features[f"metadata_{keyword}"] = len(text)
                    except Exception:
                        features['corrupted_metadata'] = 1
                        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        features['error'] = 1 
    
    return features





def check_chunks(file_path):
    frequency = {b'IHDR': 0, b'IDAT': 0, b'IEND': 0, b'sRGB': 0, b'gAMA': 0, b'pHYs': 0}
    potential = 0
    with open(file_path, 'rb') as f:
        reader = png.Reader(f)
        chunks = reader.chunks()
        for chunk_type, chunk_data in chunks:
            if chunk_type not in [b'IHDR', b'IDAT', b'IEND', b'sRGB', b'gAMA', b'pHYs']:
                print(f"Unusual chunk found: {chunk_type}, Length: {len(chunk_data)}")
            else:
                print(f"Type:  {chunk_type} Valid chunk")
                frequency[chunk_type] += 1
    
    print(frequency)

    for chunk_type, chunk_freq in frequency.items():
        if chunk_freq > 2:
            return "Suspicious number of chunks for " + chunk_type.decode() + ".", frequency
    else:
        return "PNG has passed chunk validation.", frequency


def check_metadata(file_path):
    metadata_str = ""
    with open(file_path, 'rb') as f:
        reader = png.Reader(f)
        chunks = reader.chunks()
        for chunk_type, chunk_data in chunks:
            if chunk_type in [b'tEXt', b'zTXt', b'iTXt']:
                print(f"Metadata chunk detected: {chunk_type}")

                print(f"Content: {chunk_data}")

# check_metadata(r'C:\Users\shrey\Downloads\test_file.png')
# check, frequency = check_chunks(r'C:\Users\shrey\Downloads\test_file.png')
# size_check1, validity1 = check_png_for_large_idat(r'C:\Users\shrey\Downloads\test_file.png')
# print(size_check1)
# print(validity1)
# print(check)
# print(frequency)

# check_metadata(r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Quakbot\000a04b60f05b748c8716f9bb32fdd88b06f782e0e3f2e8228c77fe1bf39de52.png')
# check1, freq1 = check_chunks(r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Quakbot\000a04b60f05b748c8716f9bb32fdd88b06f782e0e3f2e8228c77fe1bf39de52.png')
# print(check1)
# print(freq1)


def load_png_files(file_paths):
    features = []
    try:
        for file_path in file_paths:
            features.append(extract_features(file_path))
    except Exception as e:
        print(e)
    return features


# features = load_png_files(files)

# vectorizer = DictVectorizer(sparse=False)
# X = vectorizer.fit_transform(features)

# X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# clf = RandomForestClassifier()
# clf.fit(X_train, y_train)

# y_pred = clf.predict(X_test)
# print(f"Accuracy: {accuracy_score(y_test, y_pred)}")

import pickle

save_path = r'C:\Users\shrey\Documents\malware_png_detector.pkl'
vect_path = r'C:\Users\shrey\OneDrive\Documents\dict_vectorizer.pkl'

# with open(save_path, 'wb') as f:
#     pickle.dump(clf, f)

# with open(vect_path, 'wb') as f:
#     pickle.dump(vectorizer, f)


with open(save_path, 'rb') as f:
    loaded_model = pickle.load(f)

with open(vect_path, 'rb') as f:
    loaded_vectorizer = pickle.load(f)

#new_files = [r'']
# new_features = []
# # new_features = load_png_files(benign_files)
# new_features = load_png_files(mal_6)
# new_features.append(extract_features(r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Quakbot\000a04b60f05b748c8716f9bb32fdd88b06f782e0e3f2e8228c77fe1bf39de52.png'))
# new_features.append(extract_features(r'C:\Users\shrey\.cache\kagglehub\datasets\walt30\malware-images\versions\26\Quakbot\000a04b60f05b748c8716f9bb32fdd88b06f782e0e3f2e8228c77fe1bf39de52.png'))

# new_X = loaded_vectorizer.transform(new_features)

# for img in mal_9:
#     check_metadata(img)
#     check1, freq1 = check_chunks(img)
#     print(check1)
#     print(freq1)
#     size_check, validity = check_png_for_large_idat(img)
#     print(size_check)
#     if(validity == 1):
#         print("Potential malware. Size is unusual for image.")

# prediction = loaded_model.predict(new_X)
# print("Prediction (0 = benign, 1 = malicious):", prediction)


