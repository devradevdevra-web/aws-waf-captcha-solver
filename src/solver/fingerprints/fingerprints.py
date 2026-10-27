import base64
import json
import os
import time
import uuid
import zlib
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class FingerprintGenerator:
    FP_KEY = bytes([
        0x6f, 0x71, 0xa5, 0x12, 0xb1, 0xe0, 0x35, 0xea,
        0xab, 0x53, 0xd8, 0xbe, 0x73, 0x12, 0x0d, 0x3f,
        0xb6, 0x8a, 0x0c, 0xa3, 0x46, 0xb9, 0x56, 0x0a,
        0xab, 0x3e, 0x5c, 0xdf, 0x75, 0x3d, 0x5e, 0x98
    ])

    SCREEN_INFO = '1680-1050-1050-24-*-*-*'

    NEW_HISTOGRAM_BINS = [
        14472, 137, 53, 38, 42, 67, 28, 27, 38, 32, 38, 49, 43, 36, 34, 66, 57, 19, 67, 23, 23, 26, 23, 39, 48, 27, 
        44, 12, 31, 18, 48, 46, 36, 54, 26, 12, 38, 28, 24, 28, 33, 33, 16, 10, 34, 24, 11, 35, 34, 38, 34, 37, 66, 
        10, 21, 23, 20, 20, 6, 17, 48, 45, 11, 14, 20, 17, 31, 8, 15, 14, 8, 17, 17, 17, 40, 15, 11, 12, 45, 64, 29, 
        19, 19, 14, 30, 13, 15, 16, 20, 54, 30, 28, 17, 18, 12, 18, 36, 20, 23, 114, 77, 30, 542, 30, 9, 39, 31, 16, 
        16, 13, 11, 36, 23, 16, 16, 17, 15, 31, 21, 22, 71, 39, 16, 13, 30, 30, 29, 20, 24, 58, 32, 54, 22, 13, 16, 
        38, 33, 33, 70, 17, 24, 17, 12, 16, 14, 12, 26, 20, 10, 12, 60, 19, 7, 92, 11, 50, 29, 20, 9, 30, 10, 13, 
        19, 22, 50, 36, 6, 14, 9, 15, 14, 29, 18, 39, 11, 24, 61, 79, 7, 10, 9, 46, 9, 25, 9, 7, 18, 10, 7, 55, 15, 
        19, 7, 11, 61, 22, 14, 9, 65, 7, 18, 55, 37, 49, 65, 73, 85, 7, 25, 15, 8, 15, 8, 29, 37, 30, 17, 29, 21, 
        32, 27, 20, 68, 83, 33, 67, 19, 43, 53, 23, 21, 39, 14, 38, 19, 35, 35, 16, 21, 71, 125, 42, 45, 34, 63, 36, 
        33, 79, 37, 32, 78, 56, 41, 65, 98, 13133
    ]

    NEW_PLUGINS = [
        {'name': 'WebKit built-in PDF', 'str': 'WebKit built-in PDF '}, 
        {'name': 'Brave PDF plug in', 'str': 'Brave PDF plug in '}, 
        {'name': 'Ir8Hi4F', 'str': 'Ir8Hi4F 00'}, 
        {'name': 'qVp78e2b', 'str': 'qVp78e2b 292905'}, 
        {'name': 'Microsoft Edge PDF Viewer', 'str': 'Microsoft Edge PDF Viewer '}, 
        {'name': 'Chromium PDF Viewer', 'str': 'Chromium PDF Viewer '}, 
        {'name': 'PDF Viewer', 'str': 'PDF Viewer '}
    ]

    def __init__(self, user_agent: str = '', referrer: str = '', target_url: str = ''):
        self.user_agent = user_agent
        self.referrer = referrer
        self.target_url = target_url

    @staticmethod
    def _crc32(text: str) -> str:
        return f"{zlib.crc32(text.encode('utf-8')):08X}"

    def _make_base_payload(self) -> Dict[str, Any]:
        current_time_ms = int(time.time() * 1000)
        
        return {
            'metrics': {
                'fp2': 1, 'capabilities': 0, 'canvas': 12, 'gpu': 14, 'dnt': 0, 
                'math': 0, 'screen': 0, 'navigator': 0, 'subtle': 0, 'auto': 0, 
                'browser': 0, 'be': 0, 'cdp': 2, 'stealth': 0, 'formdetector': 0
            },
            'start': current_time_ms,
            'flashVersion': None,
            'plugins': [
                {'name': 'PDF Viewer', 'str': 'PDF Viewer '}, 
                {'name': 'Chromium PDF Viewer', 'str': 'Chromium PDF Viewer '}, 
                {'name': 'j47dt9e', 'str': 'j47dt9e 1312'}, 
                {'name': 'Microsoft Edge PDF Viewer', 'str': 'Microsoft Edge PDF Viewer '}, 
                {'name': 'Bny4k5cO', 'str': 'Bny4k5cO 24710570'}, 
                {'name': 'Browser Portable Document Format Plugin', 'str': 'Browser Portable Document Format Plugin '}, 
                {'name': 'WebKit built-in PDF', 'str': 'WebKit built-in PDF '}
            ],
            'dupedPlugins': 'PDF Viewer Chromium PDF Viewer j47dt9e 1312Microsoft Edge PDF Viewer Bny4k5cO 24710570Browser Portable Document Format Plugin WebKit built-in PDF ||1920-1080-1080-24-*-*-*',
            'screenInfo': '1920-1080-1080-24-*-*-*',
            'capabilities': {
                'css': {'textShadow': 1, 'WebkitTextStroke': 1, 'boxShadow': 1, 'borderRadius': 1, 'borderImage': 1, 'opacity': 1, 'transform': 1, 'transition': 1},
                'js': {'audio': True, 'geolocation': True, 'localStorage': 'supported', 'touch': False, 'video': True, 'webWorker': True},
                'elapsed': 0
            },
            'canvas': {
                'hash': 1613445327,
                'emailHash': None,
                'histogramBins': self.NEW_HISTOGRAM_BINS.copy()
            },
            'gpu': {
                'vendor': 'Brave',
                'model': 'Brave',
                'extensions': [
                    'ANGLE_instanced_arrays', 'EXT_blend_minmax', 'EXT_clip_control', 'EXT_color_buffer_half_float', 
                    'EXT_depth_clamp', 'EXT_disjoint_timer_query', 'EXT_float_blend', 'EXT_frag_depth', 
                    'EXT_polygon_offset_clamp', 'EXT_shader_texture_lod', 'EXT_texture_compression_bptc', 
                    'EXT_texture_compression_rgtc', 'EXT_texture_filter_anisotropic', 'EXT_texture_mirror_clamp_to_edge', 
                    'EXT_sRGB', 'KHR_parallel_shader_compile', 'OES_element_index_uint', 'OES_fbo_render_mipmap', 
                    'OES_standard_derivatives', 'OES_texture_float', 'OES_texture_float_linear', 'OES_texture_half_float', 
                    'OES_texture_half_float_linear', 'OES_vertex_array_object', 'WEBGL_blend_func_extended', 
                    'WEBGL_color_buffer_float', 'WEBGL_compressed_texture_s3tc', 'WEBGL_compressed_texture_s3tc_srgb', 
                    'WEBGL_debug_renderer_info', 'WEBGL_debug_shaders', 'WEBGL_depth_texture', 'WEBGL_draw_buffers', 
                    'WEBGL_lose_context', 'WEBGL_multi_draw', 'WEBGL_polygon_mode', 'EXT_circle_blender'
                ]
            },
            'dnt': None,
            'math': {'tan': '-1.4214488238747245', 'sin': '0.8178819121159085', 'cos': '-0.5753861119575491'},
            'crypto': {
                'crypto': 1, 'subtle': 1, 'encrypt': True, 'decrypt': True, 'wrapKey': True, 'unwrapKey': True, 
                'sign': True, 'verify': True, 'digest': True, 'deriveBits': True, 'deriveKey': True, 
                'getRandomValues': True, 'randomUUID': True
            },
            'automation': {
                'wd': {'properties': {'document': [], 'window': [], 'navigator': []}}, 
                'phantom': {'properties': {'window': []}}
            },
            'referrer': self.referrer,
            'userAgent': self.user_agent,
            'location': self.target_url,
            'webDriver': False,
            'be': {'si': False},
            'cdp': {'pw': [], 'pp': [], 'pf': 'na', 'cd': [], 'xb': []},
            'stealth': {'t1': 0, 't2': 0, 'i': 1, 'mte': 0, 'mtd': False},
            'formDetected': False,
            'numForms': 0,
            'numFormElements': 0,
            'end': current_time_ms + 30,
            'errors': [],
            'version': '2.4.0',
            'id': str(uuid.uuid4())
        }

    def generate_fingerprint(self) -> str:
        payload = self._make_base_payload()

        payload["metrics"].update({
            "canvas": 23, "gpu": 44, "dnt": 1,
            "browser": 1, "be": 1, "stealth": 1,
        })
        
        payload["plugins"] = self.NEW_PLUGINS
        payload["dupedPlugins"] = (
            "WebKit built-in PDF BravePDF plug in Ir8Hi4F 00"
            "qVp78e2b 292905Microsoft Edge PDF Viewer "
            "Chromium PDF Viewer PDF Viewer ||" + self.SCREEN_INFO
        )
        payload["screenInfo"] = self.SCREEN_INFO
        payload["canvas"]["hash"] = 1487839663
        payload["gpu"]["extensions"][-1] = "EXT_texture_blender"

        payload["start"] = int(time.time() * 1000) 
        payload["end"] = payload["start"] + 75
        payload["id"] = str(uuid.uuid4())

        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return f"{self._crc32(raw)}#{raw}"

    def encrypt_fingerprint(self, fingerprint: str) -> Tuple[str, str]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.FP_KEY).encrypt(nonce, fingerprint.encode("utf-8"), None)
        
        encrypted = f"{base64.b64encode(nonce).decode('ascii')}::{ciphertext.hex()}"
        checksum = fingerprint.split("#", 1)[0]
        
        return encrypted, checksum


