document.addEventListener('DOMContentLoaded', function() {
    var words = ["#HTD", "#WESERVEWHATYOUDESERVE", "#PASUMPAALNEAR ME", "#FRESHCOWMILK","#FARMTOHOME","#INAFFORDABLEPRICE","#EQUIVALENTTOMOTHERMILK","#PURECOWMILK","#COWMILKINYOURDOORSTEP"];
    var index = 0;
    var spinnerElement = document.getElementById("spinner");

    function changeWord() {
        index = (index + 1) % words.length;
        spinnerElement.textContent = words[index];
    }

    setInterval(changeWord, 3000); // Change word every 3 seconds
});
