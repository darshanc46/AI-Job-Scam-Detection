document.addEventListener("DOMContentLoaded", function() {
    const btnLoadScam = document.getElementById("btnLoadScam");
    const btnLoadSafe = document.getElementById("btnLoadSafe");
    const companyInput = document.getElementById("company_name");
    const emailInput = document.getElementById("recruiter_email");
    const roleInput = document.getElementById("job_role");
    const locationInput = document.getElementById("location");
    const descTextarea = document.getElementById("job_description");
    const fileInput = document.getElementById("document_file");
    const fileNameDisplay = document.getElementById("file_name_display");

    // Demo Sample Loader Action
    if (btnLoadScam || btnLoadSafe) {
        fetch("/api/demo-samples")
            .then(res => res.json())
            .then(data => {
                if (btnLoadScam) {
                    btnLoadScam.addEventListener("click", function() {
                        const sample = data.scam_sample;
                        if (companyInput) companyInput.value = sample.company_name;
                        if (emailInput) emailInput.value = sample.recruiter_email;
                        if (roleInput) roleInput.value = sample.job_role;
                        if (locationInput) locationInput.value = sample.location;
                        if (descTextarea) descTextarea.value = sample.job_description;
                    });
                }

                if (btnLoadSafe) {
                    btnLoadSafe.addEventListener("click", function() {
                        const sample = data.safe_sample;
                        if (companyInput) companyInput.value = sample.company_name;
                        if (emailInput) emailInput.value = sample.recruiter_email;
                        if (roleInput) roleInput.value = sample.job_role;
                        if (locationInput) locationInput.value = sample.location;
                        if (descTextarea) descTextarea.value = sample.job_description;
                    });
                }
            })
            .catch(err => console.error("Error fetching demo samples:", err));
    }

    // File Input Name Display
    if (fileInput && fileNameDisplay) {
        fileInput.addEventListener("change", function() {
            if (fileInput.files.length > 0) {
                fileNameDisplay.textContent = "📄 Selected File: " + fileInput.files[0].name;
                fileNameDisplay.style.color = "#0284c7";
            } else {
                fileNameDisplay.textContent = "";
            }
        });
    }
});
