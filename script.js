
document.getElementById('startButton').addEventListener('click', function() {
    window.location.href = "auth.html";
});

document.getElementById('contactForm').addEventListener('submit', function(event) {
    event.preventDefault();
    alert('Thank you for your message! We will get back to you shortly.');
    $('#contactModal').modal('hide');
    this.reset();
});