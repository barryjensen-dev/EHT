/**
 * Threat Visualization Map JavaScript
 * 
 * This script handles the real-time visualization of security threats on a world map.
 * It uses Leaflet.js to create the map and visualize threat data obtained from the backend.
 */

// Initialize the map when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('threat-map')) {
        initThreatMap();
    }
});

/**
 * Initialize the threat visualization map
 */
function initThreatMap() {
    // Create the map centered on the world
    const map = L.map('threat-map').setView([20, 0], 2);

    // Add OpenStreetMap tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 18
    }).addTo(map);

    // Initialize threat data
    let threatData = [];
    
    // Create layer groups for different types of threats
    const threatLayers = {
        malware: L.layerGroup().addTo(map),
        phishing: L.layerGroup().addTo(map),
        ddos: L.layerGroup().addTo(map),
        bruteforce: L.layerGroup().addTo(map),
        vulnerability: L.layerGroup().addTo(map),
        other: L.layerGroup().addTo(map)
    };
    
    // Color mapping for different threat types
    const threatColors = {
        malware: '#FF5733', // Red-orange
        phishing: '#33A1FF', // Blue
        ddos: '#FF33A1', // Pink
        bruteforce: '#A133FF', // Purple
        vulnerability: '#FFFF33', // Yellow
        other: '#33FF57' // Green
    };
    
    // Create legend
    addLegend(map, threatColors);
    
    // Fetch initial data and set up real-time updates
    fetchThreatData();
    
    // Set up periodic data updates (every 10 seconds)
    setInterval(fetchThreatData, 10000);
    
    /**
     * Fetch threat data from the server
     */
    function fetchThreatData() {
        fetch('/api/threats')
            .then(response => response.json())
            .then(data => {
                updateThreatMap(data);
            })
            .catch(error => {
                console.error('Error fetching threat data:', error);
                // Use demo data if API fails
                useDemoData();
            });
    }
    
    /**
     * Update the threat map with new data
     */
    function updateThreatMap(data) {
        // Clear existing threats from all layers
        for (const layer in threatLayers) {
            threatLayers[layer].clearLayers();
        }
        
        // Add new threats to the map
        data.forEach(threat => {
            // Create marker for the threat
            const marker = createThreatMarker(threat);
            
            // Add marker to the appropriate layer
            const layerName = threat.type.toLowerCase() in threatLayers ? 
                threat.type.toLowerCase() : 'other';
            threatLayers[layerName].addLayer(marker);
        });
        
        // Update threat counter
        updateThreatCounter(data);
        
        // Store the latest data
        threatData = data;
    }
    
    /**
     * Create a marker for a threat with popup information
     */
    function createThreatMarker(threat) {
        // Determine marker color based on threat type
        const color = threatColors[threat.type.toLowerCase()] || threatColors.other;
        
        // Create circular marker
        const marker = L.circleMarker([threat.latitude, threat.longitude], {
            radius: calculateMarkerSize(threat.severity),
            color: color,
            fillColor: color,
            fillOpacity: 0.7,
            weight: 1
        });
        
        // Create popup content with threat information
        const popupContent = `
            <div class="threat-popup">
                <h5>${threat.type} Threat</h5>
                <p><strong>Source:</strong> ${threat.source_country}</p>
                <p><strong>Target:</strong> ${threat.target_country}</p>
                <p><strong>Severity:</strong> ${getSeverityText(threat.severity)}</p>
                <p><strong>Time:</strong> ${new Date(threat.timestamp).toLocaleString()}</p>
                <p>${threat.description}</p>
            </div>
        `;
        
        // Add popup to marker
        marker.bindPopup(popupContent);
        
        // Add hover effect
        marker.on('mouseover', function() {
            this.openPopup();
        });
        
        // Return the configured marker
        return marker;
    }
    
    /**
     * Calculate marker size based on threat severity
     */
    function calculateMarkerSize(severity) {
        return 5 + (severity * 2); // Base size of 5, plus 2 per severity level
    }
    
    /**
     * Get text description of severity level
     */
    function getSeverityText(severity) {
        const levels = ['Low', 'Medium', 'High', 'Critical', 'Extreme'];
        return levels[Math.min(severity - 1, levels.length - 1)];
    }
    
    /**
     * Add a legend to the map
     */
    function addLegend(map, colors) {
        const legend = L.control({ position: 'bottomright' });
        
        legend.onAdd = function() {
            const div = L.DomUtil.create('div', 'info legend');
            
            div.innerHTML = '<h5>Threat Types</h5>';
            
            // Add legend entries for each threat type
            for (const type in colors) {
                div.innerHTML += `
                    <i style="background:${colors[type]}"></i>
                    ${type.charAt(0).toUpperCase() + type.slice(1)}<br>
                `;
            }
            
            // Add legend for severity
            div.innerHTML += '<h5 style="margin-top:10px;">Severity</h5>';
            
            // Show example circle sizes
            for (let i = 1; i <= 5; i++) {
                const size = calculateMarkerSize(i);
                div.innerHTML += `
                    <div style="display:flex;align-items:center;margin-bottom:3px;">
                        <div style="background:#999;border-radius:50%;width:${size}px;height:${size}px;margin-right:5px;"></div>
                        ${getSeverityText(i)}
                    </div>
                `;
            }
            
            return div;
        };
        
        legend.addTo(map);
    }
    
    /**
     * Update threat counter with current statistics
     */
    function updateThreatCounter(threats) {
        const counterElement = document.getElementById('threat-counter');
        if (!counterElement) return;
        
        // Count threats by type
        const counts = {
            total: threats.length,
            malware: 0,
            phishing: 0,
            ddos: 0,
            bruteforce: 0,
            vulnerability: 0,
            other: 0
        };
        
        threats.forEach(threat => {
            const type = threat.type.toLowerCase();
            if (type in counts) {
                counts[type]++;
            } else {
                counts.other++;
            }
        });
        
        // Update counter HTML
        counterElement.innerHTML = `
            <div>Total Threats: ${counts.total}</div>
            <div>Malware: ${counts.malware}</div>
            <div>Phishing: ${counts.phishing}</div>
            <div>DDoS: ${counts.ddos}</div>
            <div>Brute Force: ${counts.bruteforce}</div>
            <div>Vulnerabilities: ${counts.vulnerability}</div>
            <div>Other: ${counts.other}</div>
        `;
    }
    
    /**
     * Use demo data when API is not available
     */
    function useDemoData() {
        console.log('Using demo threat data');
        const demoData = generateDemoThreatData();
        updateThreatMap(demoData);
    }
    
    // Add filter controls
    addFilterControls(map, threatLayers);
}

/**
 * Add filter controls to the map
 */
function addFilterControls(map, layers) {
    // Create overlay control for layer toggles
    const overlays = {
        'Malware': layers.malware,
        'Phishing': layers.phishing,
        'DDoS': layers.ddos,
        'Brute Force': layers.bruteforce,
        'Vulnerabilities': layers.vulnerability,
        'Other': layers.other
    };
    
    L.control.layers(null, overlays).addTo(map);
    
    // Create timeframe filter control
    const timeControl = L.control({ position: 'topleft' });
    
    timeControl.onAdd = function() {
        const div = L.DomUtil.create('div', 'info timeframe-control');
        
        div.innerHTML = `
            <h5>Timeframe</h5>
            <select id="timeframe-select">
                <option value="3600">Last Hour</option>
                <option value="86400" selected>Last 24 Hours</option>
                <option value="604800">Last Week</option>
                <option value="2592000">Last Month</option>
            </select>
        `;
        
        return div;
    };
    
    timeControl.addTo(map);
    
    // Set up event listener for timeframe selection
    document.getElementById('timeframe-select').addEventListener('change', function() {
        const timeframe = this.value;
        fetch(`/api/threats?timeframe=${timeframe}`)
            .then(response => response.json())
            .then(data => {
                updateThreatMap(data);
            })
            .catch(error => {
                console.error('Error fetching threat data:', error);
                useDemoData();
            });
    });
}

/**
 * Generate demo threat data for testing and demonstration
 */
function generateDemoThreatData() {
    // Countries and coordinates for demo data
    const countries = [
        { name: 'United States', coords: [37.0902, -95.7129] },
        { name: 'China', coords: [35.8617, 104.1954] },
        { name: 'Russia', coords: [61.5240, 105.3188] },
        { name: 'United Kingdom', coords: [55.3781, -3.4360] },
        { name: 'Germany', coords: [51.1657, 10.4515] },
        { name: 'Brazil', coords: [-14.2350, -51.9253] },
        { name: 'Australia', coords: [-25.2744, 133.7751] },
        { name: 'India', coords: [20.5937, 78.9629] },
        { name: 'Japan', coords: [36.2048, 138.2529] },
        { name: 'Canada', coords: [56.1304, -106.3468] }
    ];
    
    // Threat types
    const threatTypes = ['malware', 'phishing', 'ddos', 'bruteforce', 'vulnerability', 'other'];
    
    // Generate 50-100 random threats
    const threatCount = Math.floor(Math.random() * 51) + 50;
    const threats = [];
    
    for (let i = 0; i < threatCount; i++) {
        // Select random source and target countries
        const sourceIndex = Math.floor(Math.random() * countries.length);
        let targetIndex = Math.floor(Math.random() * countries.length);
        
        // Ensure source and target are different
        while (targetIndex === sourceIndex) {
            targetIndex = Math.floor(Math.random() * countries.length);
        }
        
        const source = countries[sourceIndex];
        const target = countries[targetIndex];
        
        // Add some randomness to coordinates
        const sourceCoords = [
            source.coords[0] + (Math.random() * 10 - 5),
            source.coords[1] + (Math.random() * 10 - 5)
        ];
        
        // Select random threat type and severity
        const type = threatTypes[Math.floor(Math.random() * threatTypes.length)];
        const severity = Math.floor(Math.random() * 5) + 1;
        
        // Generate random timestamp within the last 24 hours
        const timestamp = new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString();
        
        // Create threat description based on type
        let description;
        switch (type) {
            case 'malware':
                description = `Detected ${['ransomware', 'trojan', 'spyware', 'worm', 'botnet'][Math.floor(Math.random() * 5)]} infection attempt`;
                break;
            case 'phishing':
                description = `${['Email', 'SMS', 'Voice', 'Social media'][Math.floor(Math.random() * 4)]} phishing campaign targeting users`;
                break;
            case 'ddos':
                description = `DDoS attack with ${Math.floor(Math.random() * 100) + 10} Gbps traffic volume`;
                break;
            case 'bruteforce':
                description = `Brute force attempt targeting ${['SSH', 'RDP', 'FTP', 'admin panel', 'API'][Math.floor(Math.random() * 5)]} services`;
                break;
            case 'vulnerability':
                description = `Exploitation attempt of ${['zero-day', 'unpatched', 'misconfigured', 'known'][Math.floor(Math.random() * 4)]} vulnerability`;
                break;
            default:
                description = `Suspicious activity detected from this location`;
        }
        
        // Create threat object
        threats.push({
            id: i + 1,
            type: type.charAt(0).toUpperCase() + type.slice(1),
            source_country: source.name,
            target_country: target.name,
            latitude: sourceCoords[0],
            longitude: sourceCoords[1],
            severity: severity,
            timestamp: timestamp,
            description: description
        });
    }
    
    return threats;
}