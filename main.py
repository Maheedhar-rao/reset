from flask import Flask, request, jsonify, send_file
import requests
import os
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_ANON_KEY')

@app.route('/')
def index():
    """Serve the reset password page"""
    return send_file('reset.html')

@app.route('/api/auth/user/reset-confirm-with-hash', methods=['POST', 'OPTIONS'])
def reset_confirm_with_hash():
    """Complete password reset using token hash from email"""
    
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
    
    try:
        data = request.get_json()
        token_hash = data.get('token_hash')
        new_password = data.get('new_password')
        
        logger.info(f"Password reset with hash")
        logger.info(f"Token hash: {token_hash[:50] if token_hash else 'None'}...")
        
        if not token_hash or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Use the token hash directly to update password
        update_headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token_hash}',
            'Content-Type': 'application/json'
        }
        
        update_url = f'{SUPABASE_URL}/auth/v1/user'
        logger.info(f"Updating password with token hash...")
        
        response = requests.put(
            update_url,
            headers=update_headers,
            json={'password': new_password},
            timeout=10
        )
        
        logger.info(f"Update response status: {response.status_code}")
        logger.info(f"Update response: {response.text}")
        
        if response.status_code == 200:
            result = jsonify({'message': 'Password updated successfully'})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, 200
        else:
            error_data = response.json() if response.text else {}
            error_msg = error_data.get('msg') or error_data.get('error_description') or error_data.get('message') or 'Failed to update password'
            logger.error(f"Password update failed: {error_msg}")
            
            result = jsonify({'error': error_msg})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, response.status_code
            
    except Exception as e:
        logger.error(f"Exception in reset_confirm_with_hash: {str(e)}", exc_info=True)
        result = jsonify({'error': str(e)})
        result.headers.add('Access-Control-Allow-Origin', '*')
        return result, 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
