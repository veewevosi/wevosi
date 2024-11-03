let map;
let group;
let ui;

function initMap() {
    // Initialize HERE Map
    const platform = new H.service.Platform({
        'apikey': window.HERE_API_KEY
    });

    const defaultLayers = platform.createDefaultLayers();
    map = new H.Map(
        document.getElementById('mapContainer'),
        defaultLayers.vector.normal.map,
        {
            zoom: 4,
            center: { lat: 39.8283, lng: -98.5795 }  // Center of USA
        }
    );

    // Add window resize handler
    window.addEventListener('resize', () => map.getViewPort().resize());

    // Add map behavior
    const behavior = new H.mapevents.Behavior(new H.mapevents.MapEvents(map));
    
    // Add UI components
    ui = H.ui.UI.createDefault(map, defaultLayers);

    // Create marker group
    group = new H.map.Group();
    map.addObject(group);

    // Add click event listener to show property info
    group.addEventListener('tap', (evt) => {
        const bubble = new H.ui.InfoBubble(evt.target.getGeometry(), {
            content: evt.target.getData()
        });
        ui.addBubble(bubble);
    });
}

function addPropertyMarker(property) {
    const marker = new H.map.Marker({
        lat: property.latitude,
        lng: property.longitude
    });

    // Create info bubble content
    const content = `
        <div class="info-bubble" style="padding: 10px;">
            <h4 style="margin: 0 0 8px 0;">${property.name}</h4>
            <p style="margin: 4px 0;">${property.address}</p>
            <p style="margin: 4px 0;">${property.type} - ${property.acres} acres</p>
        </div>
    `;

    marker.setData(content);
    group.addObject(marker);
}
