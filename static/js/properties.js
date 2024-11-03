// Define openPropertyModal function in global scope
function openPropertyModal() {
    const modal = document.getElementById('propertyModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

// Close button functionality
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('propertyModal');
    const closeBtn = document.querySelector('.close-btn');
    
    if (closeBtn && modal) {
        closeBtn.onclick = function() {
            modal.style.display = 'none';
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    }
});
