// Simple scroll reveal effect for elements with .fade-in
document.addEventListener("DOMContentLoaded", () => {
  const faders = document.querySelectorAll('.fade-in');
  const options = { threshold: 0.2 };

  const appearOnScroll = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('appear');
        observer.unobserve(entry.target);
      }
    });
  }, options);

  faders.forEach(fader => {
    appearOnScroll.observe(fader);
  });
});
