from flask import Flask, request, jsonify, send_file
import requests
import os
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_ANON_KEY')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY')  # We'll need this

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
        logger.info(f"Token hash: {token_hash}")
        logger.info(f"Token hash length: {len(token_hash)}")
        
        if not token_hash or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Try to verify the token using GET with query params
        headers = {
            'apikey': SUPABASE_KEY,
        }
        
        # Use GET request with token in query string
        verify_url = f'{SUPABASE_URL}/auth/v1/verify?token={token_hash}&type=recovery'
        logger.info(f"Verifying token with GET: {verify_url}")
        
        verify_response = requests.get(
            verify_url,
            headers=headers,
            timeout=10,
            allow_redirects=False
        )
        
        logger.info(f"Verify GET response status: {verify_response.status_code}")
        logger.info(f"Verify GET response headers: {dict(verify_response.headers)}")
        logger.info(f"Verify GET response body: {verify_response.text[:500]}")
        
        # Check if we got redirected or got a 302/303
        if verify_response.status_code in [200, 302, 303]:
            # Try to extract access token from response or Location header
            if verify_response.status_code == 200 and verify_response.text:
                try:
                    verify_data = verify_response.json()
                    access_token = verify_data.get('access_token')
                    if access_token:
                        logger.info(f"Got access token from JSON response")
                        
                        # Update password with this token
                        update_headers = {
                            'apikey': SUPABASE_KEY,
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        }
                        
                        update_response = requests.put(
                            f'{SUPABASE_URL}/auth/v1/user',
                            headers=update_headers,
                            json={'password': new_password},
                            timeout=10
                        )
                        
                        logger.info(f"Update response: {update_response.status_code} - {update_response.text}")
                        
                        if update_response.status_code == 200:
                            result = jsonify({'message': 'Password updated successfully'})
                            result.headers.add('Access-Control-Allow-Origin', '*')
                            return result, 200
                except:
                    pass
            
            # If redirect, check Location header
            location = verify_response.headers.get('Location', '')
            logger.info(f"Location header: {location}")
            
            if 'access_token=' in location:
                # Extract token from redirect URL
                import re
                match = re.search(r'access_token=([^&]+)', location)
                if match:
                    access_token = match.group(1)
                    logger.info(f"Extracted access token from Location header")
                    
                    # Update password with this token
                    update_headers = {
                        'apikey': SUPABASE_KEY,
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    }
                    
                    update_response = requests.put(
                        f'{SUPABASE_URL}/auth/v1/user',
                        headers=update_headers,
                        json={'password': new_password},
                        timeout=10
                    )
                    
                    logger.info(f"Update response: {update_response.status_code} - {update_response.text}")
                    
                    if update_response.status_code == 200:
                        result = jsonify({'message': 'Password updated successfully'})
                        result.headers.add('Access-Control-Allow-Origin', '*')
                        return result, 200
        
        # If nothing worked, return error
        return jsonify({'error': 'Could not verify recovery token. Please request a new password reset.'}), 401
            
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
