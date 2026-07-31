}  from flask import Flask, request, jsonify 
import requests 
import base64 
from datetime import datetime 
app = Flask(__name__) 
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY" 
VT_BASE_URL = "https://www.virustotal.com/api/v3" 
@app.route('/analyze', methods=['POST']) 
def analyze_url(): 
    data = request.get_json() 
    url = data.get('url') 
    if not url: 
        return jsonify({'error': 'No URL provided'}), 400 
    try: 
        headers = {"x-apikey": VT_API_KEY} 
        submit_response = requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}) 
        if submit_response.status_code != 200: 
            return jsonify({'error': 'Failed to submit URL'}), 500 
        submit_data = submit_response.json() 
        analysis_id = submit_data.get('data', {}).get('id') 
        analysis_response = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers) 
        if analysis_response.status_code != 200: 
            return jsonify({'error': 'Failed to get analysis'}), 500 
        analysis_data = analysis_response.json() 
        stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {}) 
        vendors = analysis_data.get('data', {}).get('attributes', {}).get('results', {}) 
        malicious = stats.get('malicious', 0) 
        suspicious = stats.get('suspicious', 0) 
        if malicious 
            verdict = "Malicious" 
        elif malicious  or suspicious 
            verdict = "Suspicious" 
        else: 
            verdict = "Clean" 
        vendor_results = {} 
        for vendor, result in vendors.items(): 
            if result.get('category'): 
                vendor_results[vendor] = result['category'] 
            else: 
                vendor_results[vendor] = result.get('result', 'Undetected') 
        return jsonify({ 
            'url': url, 
            'timestamp': datetime.now().isoformat(), 
            'virustotal': { 
                'stats': { 
                    'malicious': stats.get('malicious', 0), 
                    'suspicious': stats.get('suspicious', 0), 
                    'clean': stats.get('harmless', 0), 
                    'total': sum(stats.values()) 
                }, 
                'vendors': vendor_results 
            }, 
            'verdict': verdict 
        }) 
    except Exception as e: 
        return jsonify({'error': str(e)}), 500 
if __name__ == '__main__': 
    app.run(debug=True, host='0.0.0.0', port=5000) 
