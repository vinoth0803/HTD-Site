// charts.js

// Pie Chart
const ctxPie = document.getElementById('pieChart').getContext('2d');
const pieChart = new Chart(ctxPie, {
    type: 'pie',
    data: {
        labels: ['Users', 'Products', 'Customers','Reviews'],
        datasets: [{
            label: 'Distribution',
            data: [document.getElementById('total_users').value, 
                   document.getElementById('total_products').value, 
                   document.getElementById('total_samples').value,
                   document.getElementById('total_reviews').value],
            backgroundColor: ['#007bff', '#28a745', '#ffc107','#FF0000'],
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
            }
        }
    }
});

// Bar Chart
const ctxBar = document.getElementById('barChart').getContext('2d');
const barChart = new Chart(ctxBar, {
    type: 'bar',
    data: {
        labels: ['Products', 'Users', 'Customers','Reviews'],
        datasets: [{
            label: 'Count',
            data: [document.getElementById('total_products').value,
                document.getElementById('total_users').value, 
                   document.getElementById('total_samples').value,
                document.getElementById('total_reviews').value],
            backgroundColor: ['#28a745','#007bff',  '#ffc107','#FF0000'],
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});


    function closeAllCollapses() {
        // Get all elements with the class 'collapse' (all collapsible menus)
        var collapses = document.querySelectorAll('.collapse');
        // Loop through each collapsible menu and hide it
        collapses.forEach(function (collapseElement) {
            var bsCollapse = new bootstrap.Collapse(collapseElement, {
                toggle: false
            });
            bsCollapse.hide();
        });
    }

