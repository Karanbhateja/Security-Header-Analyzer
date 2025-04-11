document.addEventListener('DOMContentLoaded', function() {
  const scanForm = document.querySelector('.scan-form');
  const loaderContainer = document.querySelector('.loader-container');

  if (scanForm && loaderContainer) {
    scanForm.addEventListener('submit', function() {
      // Show the loader container
      loaderContainer.style.display = 'flex';
    });
  }
});
