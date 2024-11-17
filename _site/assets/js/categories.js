const categories = { Malware: [{ url: `/posts/reverse-engineering/`, date: `17 Nov 2024`, title: `Reverse Engineering Malware Samples`},],TryHackMe: [{ url: `/posts/ctf-writeups/`, date: `17 Nov 2024`, title: `CTF Writeups`},],HackTheBox: [{ url: `/posts/ctf-writeups/`, date: `17 Nov 2024`, title: `CTF Writeups`},],PicoCTF: [{ url: `/posts/ctf-writeups/`, date: `17 Nov 2024`, title: `CTF Writeups`},],CyberEDU: [{ url: `/posts/ctf-writeups/`, date: `17 Nov 2024`, title: `CTF Writeups`},],ROCSC: [{ url: `/posts/ctf-writeups/`, date: `17 Nov 2024`, title: `CTF Writeups`},],Software_Development: [{ url: `/posts/development-projects/`, date: `17 Nov 2024`, title: `Development Projects`},], }

console.log(categories)

window.onload = function () {
  document.querySelectorAll(".category").forEach((category) => {
    category.addEventListener("click", function (e) {
      const posts = categories[e.target.innerText.replace(" ","_")];
      let html = ``
      posts.forEach(post=>{
        html += `
        <a class="modal-article" href="${post.url}">
          <h4>${post.title}</h4>
          <small class="modal-article-date">${post.date}</small>
        </a>
        `
      })
      document.querySelector("#category-modal-title").innerText = e.target.innerText;
      document.querySelector("#category-modal-content").innerHTML = html;
      document.querySelector("#category-modal-bg").classList.toggle("open");
      document.querySelector("#category-modal").classList.toggle("open");
    });
  });

  document.querySelector("#category-modal-bg").addEventListener("click", function(){
    document.querySelector("#category-modal-title").innerText = "";
    document.querySelector("#category-modal-content").innerHTML = "";
    document.querySelector("#category-modal-bg").classList.toggle("open");
    document.querySelector("#category-modal").classList.toggle("open");
  })
};