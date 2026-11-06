'use strict';
document.getElementById('login').addEventListener('submit',async event=>{
 event.preventDefault();const code=document.getElementById('code').value;
 const error=document.getElementById('error');error.textContent='';
 try {const result=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});if(!result.ok)throw Error('Invalid access code');location.replace('/');}
 catch(e){error.textContent='Access denied. Verify the code in your local launcher.';}
});
