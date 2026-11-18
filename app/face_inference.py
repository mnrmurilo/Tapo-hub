"""Resource-limited local model service; never opens the DuckDB database."""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import struct
import threading
from face_database import CURRENT_MODEL, DIMENSIONS

SOCKET = Path("/run/tapo-face/worker.sock")
MODELS = Path("/var/lib/tapo-hub/models")
MAX_MESSAGE = 2_000_000


def sample_frames(count, fps):
    if not math.isfinite(count) or not math.isfinite(fps) or count < 1 or fps <= 0:
        raise ValueError("Invalid face clip timing")
    last = int(count) - 1
    opening = [min(last, int(fps * index / 4)) for index in range(8)]
    return sorted(set(opening + [round(last * index / 15) for index in range(16)]))


def align_face(frame, landmarks):
    """Least-squares similarity alignment to ArcFace's five-landmark template."""
    import cv2
    import numpy as np
    source = np.asarray(landmarks, dtype=np.float64)
    target = np.array([[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
                       [41.5493, 92.3655], [70.7299, 92.2041]], dtype=np.float64)
    if source.shape != (5, 2) or not np.isfinite(source).all():
        raise ValueError("Invalid face landmarks")
    mean_source, mean_target = source.mean(axis=0), target.mean(axis=0)
    centered_source, centered_target = source - mean_source, target - mean_target
    variance = (centered_source * centered_source).sum() / 5
    if variance < 1e-8:
        raise ValueError("Degenerate face landmarks")
    u, singular, vt = np.linalg.svd(centered_target.T @ centered_source / 5)
    signs = np.ones(2)
    if np.linalg.det(u @ vt) < 0:
        signs[-1] = -1
    rotation = u @ np.diag(signs) @ vt
    scale = float(singular @ signs) / variance
    matrix = np.column_stack((scale * rotation, mean_target - scale * rotation @ mean_source))
    return cv2.warpAffine(frame, matrix, (112, 112), borderValue=0)


def message(stream):
    header = stream.read(4)
    if len(header) != 4:
        raise ValueError("Missing face message")
    length = struct.unpack("!I", header)[0]
    if not 0 < length <= MAX_MESSAGE:
        raise ValueError("Face message too large")
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Truncated face message")
    return json.loads(data)


def send(connection, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError("Face response too large")
    connection.sendall(struct.pack("!I", len(data)) + data)


class FaceClient:
    def __init__(self, path=SOCKET):
        self.path = str(path)
        self.lock = threading.Lock()

    def call(self, request):
        with self.lock, socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(15)
            connection.connect(self.path)
            send(connection, request)
            with connection.makefile("rb") as stream:
                response = message(stream)
            if response.get("error"):
                raise ValueError("Face image processing rejected")
            return response

    def ready(self):
        try:
            health = self.call({"operation": "health"})
            return (health.get("ready") is True and health.get("model_id") == CURRENT_MODEL
                    and health.get("embedding_dimensions") == DIMENSIONS)
        except (OSError, ValueError):
            return False


class Engine:
    def __init__(self, models=MODELS):
        manifest = json.loads((models / "manifest.json").read_text())
        for name in ("face_detection_yunet_2023mar.onnx",):
            expected = next(row for row in manifest["models"] if row["name"] == name)
            data = (models / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise ValueError("Face model checksum mismatch")
        import cv2
        import numpy as np
        self.cv, self.np = cv2, np
        cv2.setNumThreads(1)
        cv2.ocl.setUseOpenCL(False)
        self.detector = cv2.FaceDetectorYN.create(str(models / "face_detection_yunet_2023mar.onnx"),
                                                "", (1280, 720), 0.9, 0.3, 100)
        arcface = json.loads((models / "arcface_manifest.json").read_text())
        if arcface["model_id"] != CURRENT_MODEL or arcface["embedding_dimensions"] != DIMENSIONS:
            raise ValueError("Unexpected recognition model")
        model = models / "w600k_mbf.onnx"
        if hashlib.sha256(model.read_bytes()).hexdigest() != arcface["model_sha256"]:
            raise ValueError("ArcFace model checksum mismatch")
        self.recognizer = cv2.dnn.readNetFromONNX(str(model))

    def embedding(self, aligned):
        blob = self.cv.dnn.blobFromImage(aligned, 1 / 127.5, (112, 112),
                                         (127.5, 127.5, 127.5), swapRB=True)
        self.recognizer.setInput(blob)
        feature = self.recognizer.forward().flatten()
        if feature.size != DIMENSIONS or not self.np.isfinite(feature).all():
            raise ValueError("Invalid ArcFace embedding")
        return feature.tolist()

    def faces(self, frame, limit=10):
        cv, np = self.cv, self.np
        height, width = frame.shape[:2]
        scale = min(1, 1280 / width, 1280 / height)
        preview = cv.resize(frame, (int(width * scale), int(height * scale)))
        ratios = np.array([width / preview.shape[1], height / preview.shape[0]])
        self.detector.setInputSize((preview.shape[1], preview.shape[0]))
        _, faces = self.detector.detect(preview)
        output = []
        if faces is None:
            return output
        for face in faces[:limit]:
            if min(face[2:4] * ratios) < 32 or face[-1] < 0.9:
                continue
            aligned = align_face(frame, face[4:14].reshape(5, 2) * ratios)
            sharpness = cv.Laplacian(aligned, cv.CV_64F).var()
            if sharpness < 30:
                continue
            embedding = self.embedding(aligned)
            ok, photo = cv.imencode(".jpg", aligned, [cv.IMWRITE_JPEG_QUALITY, 90])
            if not ok or photo.nbytes > 48_000:
                continue
            output.append({"embedding": embedding, "image": base64.b64encode(photo).decode(),
                           "recognizable": bool(sharpness >= 40)})
        return output

    def process(self, request):
        if request.get("operation") == "health":
            return {"ready": True, "model_id": CURRENT_MODEL, "embedding_dimensions": DIMENSIONS}
        if request.get("operation") in ("image", "reembed"):
            raw = request.get("image")
            if not isinstance(raw, str) or len(raw) > 1_400_000:
                raise ValueError("Invalid enrollment image")
            data = base64.b64decode(raw, validate=True)
            if request.get("image_format") == "nv12":
                width, height = request.get("width"), request.get("height")
                if (request["operation"] != "image" or type(width) is not int or type(height) is not int
                        or not 32 <= width <= 4096 or not 32 <= height <= 4096
                        or width % 2 or height % 2 or len(data) != width * height * 3 // 2):
                    raise ValueError("Invalid native face image")
                pixels = self.np.frombuffer(data, dtype=self.np.uint8).reshape(height * 3 // 2, width)
                frame = self.cv.cvtColor(pixels, self.cv.COLOR_YUV2BGR_NV12)
            else:
                frame = self.cv.imdecode(self.np.frombuffer(data, dtype=self.np.uint8), self.cv.IMREAD_COLOR)
            if frame is None or max(frame.shape[:2]) > 4096:
                raise ValueError("Invalid enrollment image")
            if request["operation"] == "reembed":
                if frame.shape[:2] != (112, 112):
                    raise ValueError("Invalid stored aligned face")
                return {"embedding": self.embedding(frame)}
            faces = [face for face in self.faces(frame) if face.get("recognizable", True)]
            if len(faces) != 1:
                raise ValueError("Enrollment requires one suitable face")
            return {"faces": faces}
        if request.get("operation") == "clip":
            from camera_media import STORE
            path = Path(request["path"])
            import re
            if (path.parent != STORE / "events" or not re.fullmatch(r"event-[0-9a-f]{24}\.mp4", path.name)
                    or path.is_symlink() or not path.is_file()):
                raise ValueError("Invalid face clip")
            capture = self.cv.VideoCapture(str(path), self.cv.CAP_FFMPEG, [self.cv.CAP_PROP_N_THREADS, 1])
            output = []
            try:
                count = capture.get(self.cv.CAP_PROP_FRAME_COUNT)
                frames = sample_frames(count, capture.get(self.cv.CAP_PROP_FPS))
                first = request.get("sample_start", 0)
                if type(first) is not int or not 0 <= first < len(frames):
                    raise ValueError("Invalid face sample cursor")
                end = min(first+4, len(frames)) if "sample_start" in request else len(frames)
                for index in frames[first:end]:
                    capture.set(self.cv.CAP_PROP_POS_FRAMES, index)
                    ok, frame = capture.read()
                    if not ok and index == int(count) - 1 and index > 0:
                        # OpenCV can seek past EOF on VFR MP4s; decode a bounded tail instead.
                        capture.set(self.cv.CAP_PROP_POS_FRAMES, max(0, index - 30))
                        for _ in range(32):
                            decoded, candidate = capture.read()
                            if not decoded:
                                break
                            ok, frame = True, candidate
                    if not ok:
                        raise ValueError("Face clip decoding failed")
                    output.extend(self.faces(frame, limit=min(10, 20-len(output))))
                    if len(output) >= 20:
                        break
            finally:
                capture.release()
            return {"faces": output[:20], "next_sample": end if end < len(frames) and len(output) < 20 else None}
        raise ValueError("Unknown face operation")


def serve():
    engine = Engine()
    if SOCKET.exists() and not SOCKET.is_socket():
        raise ValueError("Unsafe face socket path")
    SOCKET.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(SOCKET))
        os.chmod(SOCKET, 0o600)
        server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(15)
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.getuid():
                    continue
                try:
                    with connection.makefile("rb") as stream:
                        request = message(stream)
                    send(connection, engine.process(request))
                except Exception:
                    # Never send model exceptions, images or embeddings to logs.
                    try:
                        send(connection, {"error": "processing_failed"})
                    except OSError:
                        pass


if __name__ == "__main__":
    serve()
