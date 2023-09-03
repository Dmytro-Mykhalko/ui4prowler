// handle navigation and content display
document.addEventListener("DOMContentLoaded", function() {
    // Function to show the appropriate section based on the URL hash
    function showSectionBasedOnHash() {
        var targetSectionId = window.location.hash.substring(1);
        var targetSection = document.getElementById(targetSectionId);

        console.log(targetSection);
        if (targetSection) {
            var sections = document.querySelectorAll("section");
            for (var i = 0; i < sections.length; i++) {
                sections[i].style.display = "none";
            }
            targetSection.style.display = "block";
        }
    }

    // Call the function initially to show the section based on the URL hash
    showSectionBasedOnHash();

    // Attach event listener to handle hash changes
    window.addEventListener("hashchange", showSectionBasedOnHash);

    // accordion
    const accordionTitles = document.querySelectorAll(".accordion-item-title");

    accordionTitles.forEach((title) => {
        title.addEventListener("click", (e) => {
            const content = title.parentElement;
            content.classList.toggle("open");
            console.log(content);
        });
    });
    
});

function copyToClipboard(copyText) {
    console.log("Started");

    console.log(copyText);

  
     // Copy the text inside the text field
    navigator.clipboard.writeText(copyText);
  
    // Alert the copied text
    alert("Copied the text: " + copyText.value);
}