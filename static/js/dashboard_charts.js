document.addEventListener("DOMContentLoaded", function() {
    const riskChartCanvas = document.getElementById("riskDistributionChart");
    const categoryChartCanvas = document.getElementById("scamCategoryChart");

    if (riskChartCanvas && categoryChartCanvas) {
        fetch("/api/analytics")
            .then(res => res.json())
            .then(data => {
                // Render Doughnut Chart for Safe vs Scam Ratio
                new Chart(riskChartCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: ['Safe Postings', 'Scam Alerts'],
                        datasets: [{
                            data: [data.safe_count, data.scam_count],
                            backgroundColor: ['#10b981', '#ef4444'],
                            borderWidth: 2,
                            borderColor: '#0f172a'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { labels: { color: '#f8fafc', font: { family: 'Inter' } } }
                        }
                    }
                });

                // Render Bar Chart for Scam Categories Breakdown
                const catLabels = Object.keys(data.categories);
                const catValues = Object.values(data.categories);

                new Chart(categoryChartCanvas, {
                    type: 'bar',
                    data: {
                        labels: catLabels.length > 0 ? catLabels : ['No Threats Detected'],
                        datasets: [{
                            label: 'Detections Count',
                            data: catValues.length > 0 ? catValues : [0],
                            backgroundColor: '#0284c7',
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
                            y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } }
                        },
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });
            })
            .catch(err => console.error("Error loading analytics data:", err));
    }
});
