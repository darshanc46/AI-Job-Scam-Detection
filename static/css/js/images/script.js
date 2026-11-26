// ================================
// Animated Statistics
// ================================

function counter(id, start, end, speed, suffix = "") {

    const obj = document.getElementById(id);

    if (!obj) return;

    let current = start;

    const timer = setInterval(() => {

        current++;

        obj.innerHTML = current + suffix;

        if (current >= end) {

            clearInterval(timer);

        }

    }, speed);

}

counter("jobs", 0, 10, 100, "K+");
counter("students", 0, 2500, 1, "+");
counter("accuracy", 0, 98, 30, "%");


// ================================
// Typing Animation
// ================================

const words = [

"AI Powered Job Scam Detection",

"Internship Scam Detection",

"Protect Your Career",

"Safe Job Verification"

];

let wordIndex = 0;
let charIndex = 0;

const typing = document.getElementById("typing");

function typeEffect(){

    if(!typing) return;

    if(charIndex < words[wordIndex].length){

        typing.innerHTML += words[wordIndex].charAt(charIndex);

        charIndex++;

        setTimeout(typeEffect,100);

    }else{

        setTimeout(deleteEffect,1500);

    }

}

function deleteEffect(){

    if(charIndex>0){

        typing.innerHTML=words[wordIndex].substring(0,charIndex-1);

        charIndex--;

        setTimeout(deleteEffect,50);

    }else{

        wordIndex++;

        if(wordIndex>=words.length){

            wordIndex=0;

        }

        setTimeout(typeEffect,300);

    }

}

typeEffect();


// ================================
// Progress Bar
// ================================

window.onscroll = function(){

    const bar = document.getElementById("progressBar");

    if(!bar) return;

    let winScroll = document.body.scrollTop || document.documentElement.scrollTop;

    let height = document.documentElement.scrollHeight - document.documentElement.clientHeight;

    let scrolled = (winScroll / height) * 100;

    bar.style.width = scrolled + "%";

};

// ================================
// Live Clock
// ================================

function updateClock(){

    const clock = document.getElementById("clock");

    if(!clock) return;

    let now = new Date();

    clock.innerHTML =
    now.toLocaleDateString() + " | " + now.toLocaleTimeString();

}

setInterval(updateClock,1000);

updateClock();


// ================================
// Chatbot
// ================================

const chatBtn = document.getElementById("chatBtn");

if(chatBtn){

    chatBtn.onclick = function(){

        alert("Button is working!");

    };

}

function sendQuestion(question){

    const answer = document.getElementById("answer");

    if(!answer) return;

    if(question=="fake"){

        answer.innerHTML="⚠ Never pay registration fees. Verify the company website before applying.";

    }

    else if(question=="safe"){

        answer.innerHTML="✅ Genuine companies never ask for registration fees.";

    }

    else if(question=="resume"){

        answer.innerHTML="📄 Keep your resume updated and apply through trusted job portals.";

    }

    else{

        answer.innerHTML="🤖 I can help detect fake jobs and internships.";

    }

}


