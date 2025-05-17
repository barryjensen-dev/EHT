/**
 * Threat Visualization Map JavaScript
 * 
 * This script handles the real-time visualization of security threats on a world map.
 * It uses Leaflet.js to create the map and visualize threat data obtained from the AlienVault OTX API.
 */

// Initialize the map and global variables when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('threat-map')) {
        initThreatMap();
        initDetailsView();
    }
});

// Global variables to store threat data and filters
let globalThreatData = [];
let activeFilters = {
    timeframe: "86400",
    severity: "all",
    type: "all",
    country: "all",
    indicator: "all",
    search: ""
};

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
    
    // Fetch initial data 
    fetchThreatData();
    
    // Set up periodic data updates (every 30 seconds)
    setInterval(fetchThreatData, 30000);
    
    /**
     * Fetch threat data from the server with filters
     */
    function fetchThreatData() {
        // Build query string with filters
        const queryParams = new URLSearchParams({
            timeframe: activeFilters.timeframe
        });
        
        fetch(`/api/threats?${queryParams.toString()}`)
            .then(response => response.json())
            .then(data => {
                // Store the full data set
                globalThreatData = data;
                
                // Apply client-side filters and update map
                const filteredData = applyFilters(data);
                updateThreatMap(filteredData);
                
                // Update statistics view
                updateStatistics(data);
                
                // Update details view if visible
                updateDetailsView(filteredData);
            })
            .catch(error => {
                console.error('Error fetching threat data:', error);
            });
    }
    
    /**
     * Apply filters to the threat data
     */
    function applyFilters(data) {
        return data.filter(threat => {
            // Filter by severity
            if (activeFilters.severity !== "all" && threat.severity != activeFilters.severity) {
                return false;
            }
            
            // Filter by threat type
            if (activeFilters.type !== "all" && threat.type !== activeFilters.type) {
                return false;
            }
            
            // Filter by country
            if (activeFilters.country !== "all" && 
                threat.source_country !== activeFilters.country && 
                threat.target_country !== activeFilters.country) {
                return false;
            }
            
            // Filter by indicator type
            if (activeFilters.indicator !== "all" && 
                (!threat.indicator_type || threat.indicator_type !== activeFilters.indicator)) {
                return false;
            }
            
            // Filter by search term
            if (activeFilters.search && activeFilters.search.length > 0) {
                const searchTerm = activeFilters.search.toLowerCase();
                
                // Check various fields for the search term
                const descriptionMatch = threat.description && threat.description.toLowerCase().includes(searchTerm);
                const sourceMatch = threat.source_country && threat.source_country.toLowerCase().includes(searchTerm);
                const targetMatch = threat.target_country && threat.target_country.toLowerCase().includes(searchTerm);
                const indicatorMatch = threat.indicator_value && threat.indicator_value.toLowerCase().includes(searchTerm);
                const typeMatch = threat.type && threat.type.toLowerCase().includes(searchTerm);
                
                // Include threat if any field matches
                if (!(descriptionMatch || sourceMatch || targetMatch || indicatorMatch || typeMatch)) {
                    return false;
                }
            }
            
            // Include threat if it passes all filters
            return true;
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
        
        // Build indicator info if available
        let indicatorInfo = '';
        if (threat.indicator_type && threat.indicator_value) {
            indicatorInfo = `<p><strong>Indicator:</strong> ${threat.indicator_type} - ${threat.indicator_value}</p>`;
        }
        
        // Build tags display if available
        let tagsDisplay = '';
        if (threat.tags && threat.tags.length > 0) {
            tagsDisplay = '<p><strong>Tags:</strong> ' + 
                threat.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join(' ') + 
                '</p>';
        }
        
        // View details button
        const viewDetailsButton = threat.pulse_id ? 
            `<button class="btn btn-sm btn-primary mt-2" onclick="showThreatDetails('${threat.id}')">View Details</button>` : '';
        
        // Create popup content with threat information
        const popupContent = `
            <div class="threat-popup">
                <h5>${threat.type} Threat</h5>
                <p><strong>Source:</strong> ${threat.source_country}</p>
                <p><strong>Target:</strong> ${threat.target_country}</p>
                <p><strong>Severity:</strong> ${getSeverityText(threat.severity)}</p>
                <p><strong>Time:</strong> ${new Date(threat.timestamp).toLocaleString()}</p>
                ${indicatorInfo}
                <p>${threat.description}</p>
                ${tagsDisplay}
                ${viewDetailsButton}
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
    
    // Add filter controls to the map
    L.control.layers(null, {
        'Malware': threatLayers.malware,
        'Phishing': threatLayers.phishing,
        'DDoS': threatLayers.ddos,
        'Brute Force': threatLayers.bruteforce,
        'Vulnerabilities': threatLayers.vulnerability,
        'Other': threatLayers.other
    }).addTo(map);
    
    // Set up event listeners for the filter controls
    document.getElementById('timeframe-filter').addEventListener('change', function() {
        activeFilters.timeframe = this.value;
        fetchThreatData(); // Refetch data with new timeframe
    });
    
    document.getElementById('severity-filter').addEventListener('change', function() {
        activeFilters.severity = this.value;
        updateUI();
    });
    
    document.getElementById('type-filter').addEventListener('change', function() {
        activeFilters.type = this.value;
        updateUI();
    });
    
    document.getElementById('country-filter').addEventListener('change', function() {
        activeFilters.country = this.value;
        updateUI();
    });
    
    document.getElementById('indicator-filter').addEventListener('change', function() {
        activeFilters.indicator = this.value;
        updateUI();
    });
    
    document.getElementById('search-filter').addEventListener('input', function() {
        activeFilters.search = this.value;
    });
    
    document.getElementById('apply-filters').addEventListener('click', function() {
        updateUI();
    });
    
    document.getElementById('reset-filters').addEventListener('click', function() {
        // Reset all filters to default values
        activeFilters = {
            timeframe: "86400",
            severity: "all",
            type: "all",
            country: "all",
            indicator: "all",
            search: ""
        };
        
        // Reset the form controls
        document.getElementById('timeframe-filter').value = "86400";
        document.getElementById('severity-filter').value = "all";
        document.getElementById('type-filter').value = "all";
        document.getElementById('country-filter').value = "all";
        document.getElementById('indicator-filter').value = "all";
        document.getElementById('search-filter').value = "";
        
        // Update the UI with all threats
        updateUI();
    });
    
    // Function to update UI elements based on current filters
    function updateUI() {
        const filteredData = applyFilters(globalThreatData);
        updateThreatMap(filteredData);
        updateDetailsView(filteredData);
    }
}

/**
 * Initialize the details view with event handlers
 */
function initDetailsView() {
    // Set up view toggle buttons
    document.getElementById('view-map-btn').addEventListener('click', function() {
        document.getElementById('map-view').classList.remove('d-none');
        document.getElementById('stats-view').classList.add('d-none');
        document.getElementById('details-view').classList.add('d-none');
        this.classList.add('active');
        document.getElementById('view-stats-btn').classList.remove('active');
        document.getElementById('view-details-btn').classList.remove('active');
    });
    
    document.getElementById('view-stats-btn').addEventListener('click', function() {
        document.getElementById('stats-view').classList.remove('d-none');
        document.getElementById('map-view').classList.add('d-none');
        document.getElementById('details-view').classList.add('d-none');
        this.classList.add('active');
        document.getElementById('view-map-btn').classList.remove('active');
        document.getElementById('view-details-btn').classList.remove('active');
        
        // Update statistics when switching to stats view
        updateStatistics(globalThreatData);
    });
    
    document.getElementById('view-details-btn').addEventListener('click', function() {
        document.getElementById('details-view').classList.remove('d-none');
        document.getElementById('map-view').classList.add('d-none');
        document.getElementById('stats-view').classList.add('d-none');
        this.classList.add('active');
        document.getElementById('view-map-btn').classList.remove('active');
        document.getElementById('view-stats-btn').classList.remove('active');
        
        // Update details view when switching to it
        const filteredData = applyFilters(globalThreatData);
        updateDetailsView(filteredData);
    });
    
    // Set up refresh button
    document.getElementById('refresh-threats').addEventListener('click', function() {
        fetchThreatData();
    });
    
    // Set up export button
    document.getElementById('export-threats').addEventListener('click', function() {
        exportThreatsToCSV();
    });
}

/**
 * Update the details view with the filtered threat data
 */
function updateDetailsView(threats) {
    const tableBody = document.getElementById('threat-details-table');
    const showingText = document.getElementById('showing-threats');
    
    if (!tableBody || !showingText || threats.length === 0) {
        if (tableBody) {
            tableBody.innerHTML = '<tr><td colspan="8" class="text-center py-4">No threats match the current filters</td></tr>';
        }
        if (showingText) {
            showingText.textContent = 'Showing 0 threats';
        }
        return;
    }
    
    // Update the showing text
    showingText.textContent = `Showing ${threats.length} threat${threats.length > 1 ? 's' : ''}`;
    
    // Clear the table
    tableBody.innerHTML = '';
    
    // Add each threat to the table
    threats.forEach(threat => {
        const row = document.createElement('tr');
        
        // Get indicator info
        const indicatorInfo = threat.indicator_type && threat.indicator_value ? 
            `${threat.indicator_type}: ${threat.indicator_value}` : 'N/A';
        
        // Create action buttons
        const viewButton = `<button class="btn btn-sm btn-primary me-1" onclick="showThreatDetails('${threat.id}')">View</button>`;
        const pulseLink = threat.pulse_url ? 
            `<a href="${threat.pulse_url}" class="btn btn-sm btn-info" target="_blank">OTX</a>` : '';
        
        // Set row HTML
        row.innerHTML = `
            <td>${threat.id}</td>
            <td>${threat.type}</td>
            <td>${indicatorInfo}</td>
            <td>${threat.source_country}</td>
            <td><span class="badge ${getSeverityBadgeClass(threat.severity)}">${getSeverityText(threat.severity)}</span></td>
            <td>${new Date(threat.timestamp).toLocaleString()}</td>
            <td title="${threat.description}">${truncateText(threat.description, 50)}</td>
            <td>${viewButton} ${pulseLink}</td>
        `;
        
        tableBody.appendChild(row);
    });
}

/**
 * Update statistics based on threat data
 */
function updateStatistics(data) {
    // Count threats by type
    const typeCounts = {
        'Malware': 0,
        'Phishing': 0,
        'DDoS': 0,
        'Bruteforce': 0,
        'Vulnerability': 0,
        'Other': 0
    };
    
    // Count threats by severity
    const severityCounts = {
        1: 0, // Low
        2: 0, // Medium
        3: 0, // High
        4: 0, // Critical
        5: 0  // Extreme
    };
    
    // Count source and target countries
    const sourceCounts = {};
    const targetCounts = {};
    
    // Count indicator types
    const indicatorCounts = {};
    
    // Process each threat
    data.forEach(threat => {
        // Count by type
        if (threat.type in typeCounts) {
            typeCounts[threat.type]++;
        } else {
            typeCounts['Other']++;
        }
        
        // Count by severity
        severityCounts[threat.severity]++;
        
        // Count countries
        sourceCounts[threat.source_country] = (sourceCounts[threat.source_country] || 0) + 1;
        targetCounts[threat.target_country] = (targetCounts[threat.target_country] || 0) + 1;
        
        // Count indicator types
        if (threat.indicator_type) {
            indicatorCounts[threat.indicator_type] = (indicatorCounts[threat.indicator_type] || 0) + 1;
        }
    });
    
    // Update type counts
    document.getElementById('malware-count').textContent = typeCounts['Malware'];
    document.getElementById('phishing-count').textContent = typeCounts['Phishing'];
    document.getElementById('ddos-count').textContent = typeCounts['DDoS'];
    document.getElementById('bruteforce-count').textContent = typeCounts['Bruteforce'];
    document.getElementById('vulnerability-count').textContent = typeCounts['Vulnerability'];
    document.getElementById('other-count').textContent = typeCounts['Other'];
    
    // Update severity counts
    document.getElementById('low-severity').textContent = severityCounts[1];
    document.getElementById('medium-severity').textContent = severityCounts[2];
    document.getElementById('high-severity').textContent = severityCounts[3];
    document.getElementById('critical-severity').textContent = severityCounts[4];
    document.getElementById('extreme-severity').textContent = severityCounts[5];
    
    // Update top source countries
    updateTopCountries('top-sources', sourceCounts);
    
    // Update top target countries
    updateTopCountries('top-targets', targetCounts);
    
    // Update indicator distribution
    updateIndicatorDistribution(indicatorCounts);
}

/**
 * Update top countries display
 */
function updateTopCountries(elementId, countryCounts) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.innerHTML = '';
    
    // Sort countries by count and take top 6
    Object.entries(countryCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .forEach(([country, count]) => {
            const div = document.createElement('div');
            div.className = 'stat-item';
            div.innerHTML = `
                <div class="number">${count}</div>
                <div class="label">${country}</div>
            `;
            element.appendChild(div);
        });
}

/**
 * Update indicator distribution display
 */
function updateIndicatorDistribution(indicatorCounts) {
    const element = document.getElementById('indicator-distribution');
    if (!element) return;
    
    element.innerHTML = '';
    
    // If no indicators, show message
    if (Object.keys(indicatorCounts).length === 0) {
        element.innerHTML = '<p class="text-center">No indicator data available</p>';
        return;
    }
    
    // Sort indicators by count and display all
    Object.entries(indicatorCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([indicator, count]) => {
            const div = document.createElement('div');
            div.className = 'stat-item';
            div.innerHTML = `
                <div class="number">${count}</div>
                <div class="label">${indicator}</div>
            `;
            element.appendChild(div);
        });
}

/**
 * Show detailed information about a specific threat
 */
function showThreatDetails(threatId) {
    // Find the threat in the global data
    const threat = globalThreatData.find(t => t.id == threatId);
    if (!threat) {
        console.error('Threat not found:', threatId);
        return;
    }
    
    // Populate modal content
    const modalContent = document.getElementById('threat-detail-content');
    
    // Format tags display
    let tagsHtml = '';
    if (threat.tags && threat.tags.length > 0) {
        tagsHtml = `
            <div class="mb-3">
                <h6>Tags:</h6>
                <div>${threat.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join(' ')}</div>
            </div>
        `;
    }
    
    // Format indicator info
    let indicatorHtml = '';
    if (threat.indicator_type && threat.indicator_value) {
        indicatorHtml = `
            <div class="mb-3">
                <h6>Indicator:</h6>
                <div><strong>${threat.indicator_type}:</strong> ${threat.indicator_value}</div>
            </div>
        `;
    }
    
    // Build content HTML
    modalContent.innerHTML = `
        <div class="row">
            <div class="col-12 mb-3">
                <h5>${threat.type} Threat</h5>
                <p class="mb-1">${threat.description}</p>
            </div>
            
            <div class="col-md-6">
                <div class="mb-3">
                    <h6>Severity:</h6>
                    <span class="badge ${getSeverityBadgeClass(threat.severity)}">${getSeverityText(threat.severity)}</span>
                </div>
                
                <div class="mb-3">
                    <h6>Source Country:</h6>
                    <p>${threat.source_country}</p>
                </div>
                
                <div class="mb-3">
                    <h6>Target Country:</h6>
                    <p>${threat.target_country}</p>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="mb-3">
                    <h6>Timestamp:</h6>
                    <p>${new Date(threat.timestamp).toLocaleString()}</p>
                </div>
                
                ${indicatorHtml}
                
                ${tagsHtml}
            </div>
            
            <div class="col-12 mt-2">
                <div id="threat-detail-map" style="height: 200px;"></div>
            </div>
        </div>
    `;
    
    // Set up link to OTX pulse
    const pulseButton = document.getElementById('view-pulse-btn');
    if (threat.pulse_url) {
        pulseButton.href = threat.pulse_url;
        pulseButton.style.display = 'block';
    } else {
        pulseButton.style.display = 'none';
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('threatDetailModal'));
    modal.show();
    
    // Initialize the detail map after modal is shown
    document.getElementById('threatDetailModal').addEventListener('shown.bs.modal', function () {
        const detailMap = L.map('threat-detail-map').setView([threat.latitude, threat.longitude], 5);
        
        // Add OpenStreetMap tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 18
        }).addTo(detailMap);
        
        // Determine marker color based on threat type
        const threatColors = {
            'Malware': '#FF5733',
            'Phishing': '#33A1FF',
            'DDoS': '#FF33A1',
            'Bruteforce': '#A133FF',
            'Vulnerability': '#FFFF33',
            'Other': '#33FF57'
        };
        
        const color = threatColors[threat.type] || threatColors.Other;
        
        // Add marker for the threat source
        L.circleMarker([threat.latitude, threat.longitude], {
            radius: 8 + (threat.severity * 2),
            color: color,
            fillColor: color,
            fillOpacity: 0.7,
            weight: 1
        }).addTo(detailMap);
    });
}

/**
 * Export current threat data to CSV
 */
function exportThreatsToCSV() {
    // Get filtered threats
    const filteredThreats = applyFilters(globalThreatData);
    
    if (filteredThreats.length === 0) {
        alert('No threat data to export.');
        return;
    }
    
    // Define CSV columns
    const columns = ['ID', 'Type', 'Indicator Type', 'Indicator Value', 'Source Country', 
                     'Target Country', 'Severity', 'Timestamp', 'Description'];
    
    // Create CSV header
    let csvContent = columns.join(',') + '\n';
    
    // Add each threat as a row
    filteredThreats.forEach(threat => {
        const row = [
            threat.id,
            threat.type,
            threat.indicator_type || 'N/A',
            (threat.indicator_value || 'N/A').replace(/,/g, ' '), // Remove commas to avoid CSV issues
            threat.source_country,
            threat.target_country,
            threat.severity,
            threat.timestamp,
            (threat.description || '').replace(/,/g, ' ').replace(/\n/g, ' ') // Clean description
        ];
        
        csvContent += row.join(',') + '\n';
    });
    
    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `threat_data_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

/**
 * Helper function to get text description of severity level
 */
function getSeverityText(severity) {
    const levels = ['Low', 'Medium', 'High', 'Critical', 'Extreme'];
    return levels[Math.min(severity - 1, levels.length - 1)];
}

/**
 * Helper function to get severity badge class
 */
function getSeverityBadgeClass(severity) {
    const classes = ['bg-success', 'bg-info', 'bg-warning', 'bg-danger', 'bg-dark'];
    return classes[Math.min(severity - 1, classes.length - 1)];
}

/**
 * Helper function to truncate text with ellipsis
 */
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}