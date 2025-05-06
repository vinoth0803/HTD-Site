// Function to format the date
function formatDate(date) {
    const options = { day: '2-digit', month: '2-digit', year: 'numeric' };
    return date.toLocaleDateString('en-GB', options); // Format as DD-MM-YYYY
}

// Get the current date
const currentDate = new Date();

// Set the current date in the span
document.getElementById('update-date').textContent = formatDate(currentDate);
