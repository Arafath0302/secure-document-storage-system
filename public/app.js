document.getElementById("uploadForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = e.target.querySelector("input[name='file']");
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    const response = await fetch("/upload", {
        method: "POST",
        body: formData,
    });

    const data = await response.json();

    if (data.encryptedAesKey) {
        const keyDisplay = document.getElementById("keyDisplay");
        keyDisplay.innerHTML = `
            Encryption Key: <span id="encryptionKey">${data.encryptedAesKey}</span>
            <button id="copyKeyButton">Copy</button>
        `;
        keyDisplay.style.display = "block";

        // Add event listener for the "Copy" button
        document.getElementById("copyKeyButton").addEventListener("click", () => {
            const encryptionKey = document.getElementById("encryptionKey").innerText;
            navigator.clipboard.writeText(encryptionKey)
                .then(() => {
                    alert("Encryption key copied to clipboard!");
                })
                .catch((err) => {
                    console.error("Error copying key:", err);
                });
        });
    } else {
        alert("Error: Encryption key not generated properly.");
    }
});

document.getElementById("downloadForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileId = document.getElementById("fileIdInput").value;
    const encryptedAesKey = document.getElementById("keyInput").value;

    const response = await fetch("/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fileId, encryptedAesKey }),
    });

    if (response.ok) {
        const blob = await response.blob();
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = 'downloaded-file';
        link.click();
    } else {
        alert(await response.text());
    }
});
