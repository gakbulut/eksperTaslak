// script18.js dosyası

/* left column - stacked menu*/
function openCity_left(evt, cityName) {
  var i, tabcontent_left, tablinks_left;
  tabcontent_left = document.getElementsByClassName("tabcontent_left");
  for (i = 0; i < tabcontent_left.length; i++) {
    tabcontent_left[i].style.display = "none";
  }
  tablinks_left = document.getElementsByClassName("tablinks_left");
  for (i = 0; i < tablinks_left.length; i++) {
    tablinks_left[i].className = tablinks_left[i].className.replace(
      " active",
      ""
    );
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
};
// Get the element with id="defaultOpen_left" and click on it
document.getElementById("defaultOpen_left").click();

/* right column - stacked menu*/
function openCity_right(evt, cityName) {
  var i, tabcontent_right, tablinks_right;
  tabcontent_right = document.getElementsByClassName("tabcontent_right");
  for (i = 0; i < tabcontent_right.length; i++) {
    tabcontent_right[i].style.display = "none";
  }
  tablinks_right = document.getElementsByClassName("tablinks_right");
  for (i = 0; i < tablinks_right.length; i++) {
    tablinks_right[i].className = tablinks_right[i].className.replace(
      " active",
      ""
    );
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
};
// Get the element with id="defaultOpen_right" and click on it
document.getElementById("defaultOpen_right").click();

/* right column - accordion menu*/
var acc = document.getElementsByClassName("accordion");
var i;
// for (i = 0; i < acc.length; i++) {
//   acc[i].addEventListener("click", function () {
//     /* Toggle between adding and removing the "active" class,
//         to highlight the button that controls the panel */
//     this.classList.toggle("active");

//     /* Toggle between hiding and showing the active panel */
//     var panel = this.nextElementSibling;
//     if (panel.style.display === "block") {
//       panel.style.display = "none";
//     } else {
//       panel.style.display = "block";
//     }
//   });
// };

// ***** Close Other Panels ******
for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function () {
    for (var j = 0; j < acc.length; j++) {
      if (acc[j] !== this) {
        acc[j].classList.remove("active");
        acc[j].nextElementSibling.style.display = "none";
        acc[j].setAttribute("aria-expanded", "false");
      }
    }
    this.classList.toggle("active");
    var panel = this.nextElementSibling;
    var isOpen = panel.style.display === "block";
    panel.style.display = isOpen ? "none" : "block";
    this.setAttribute("aria-expanded", !isOpen);

    // Ensure the clicked panel is in view when it opens
    if (!isOpen) {
      setTimeout(function () {
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 100); // Allow time for the panel to be displayed first
    }
  });
};

document.querySelectorAll("#defaultOpen_left").forEach((element) => {
  element.click();
});

// Dinamik menü - Item(öğe) ekleme
/**
 * Adds a new menu item to the specified menu.
 *
 * @param {HTMLElement} menu - The menu element to which the new item will be added.
 * @param {string} itemId - The ID to be assigned to the new menu item.
 * @param {string} inputId - The ID to be assigned to the new input element.
 * @param {string} selectId - The ID to be assigned to the new select element.
 * @param {Array} selectOptions - An array of options for the select element, where each option is an object with 'value' and 'text' properties.
 * @param {string} range1 - The ID to be assigned to the new range1 element.
 * @param {string} range2 - The ID to be assigned to the new range2 element.
 * @param {string} placeholderr - The ID to be assigned to the new placeholderr element.
 */

// Dinamik menü - Item(öğe) ekleme "Ulaşım Yolları ve Kat Düzeni"
function addMenuItem(
  menu,
  itemId,
  inputId,
  selectId,
  selectOptions,
  range1,
  range2,
  placeholderr
) {
  const newMenuItemRow = document.createElement("div");
  const newMenuItemDivCol60 = document.createElement("div");
  const newMenuItemDivCol60Input = document.createElement("input");
  const newMenuItemDivCol30 = document.createElement("div");
  const newMenuItemDivCol30Select = document.createElement("select");
  const newMenuItemDivCol10 = document.createElement("div");
  const newMenuItemDivCol10Button = document.createElement("button");
  const newMenuItemDivCol10ButtonSpan = document.createElement("span");

  newMenuItemRow.className = "row";
  newMenuItemRow.id = itemId;
  newMenuItemDivCol60.className = range1;
  newMenuItemDivCol60Input.type = "text";
  newMenuItemDivCol60Input.id = inputId;
  newMenuItemDivCol60Input.name = inputId;
  newMenuItemDivCol60Input.placeholder = placeholderr;
  newMenuItemDivCol30.className = range2;
  newMenuItemDivCol30Select.id = selectId;
  newMenuItemDivCol30Select.name = selectId;
  newMenuItemDivCol10.className = "col-10";
  newMenuItemDivCol10.style.marginTop = "4px";
  newMenuItemDivCol10Button.type = "button";
  newMenuItemDivCol10Button.id = "addMenuItemDeleted";

  newMenuItemDivCol10Button.onclick = function () {
    //menu.removeChild(newMenuItemRow);
    menu.removeChild(menu.lastElementChild);
  };

  newMenuItemDivCol10ButtonSpan.className = "material-symbols-outlined";
  newMenuItemDivCol10ButtonSpan.textContent = "delete";

  // Append select options
  selectOptions.forEach((option) => {
    const opt = document.createElement("option");
    opt.value = option.value;
    opt.textContent = option.text;
    newMenuItemDivCol30Select.appendChild(opt);
  });

  // Append elements to create the structure
  menu.appendChild(newMenuItemRow);
  newMenuItemRow.appendChild(newMenuItemDivCol60);
  newMenuItemDivCol60.appendChild(newMenuItemDivCol60Input);
  newMenuItemRow.appendChild(newMenuItemDivCol30);
  newMenuItemDivCol30.appendChild(newMenuItemDivCol30Select);
  newMenuItemRow.appendChild(newMenuItemDivCol10);
  newMenuItemDivCol10.appendChild(newMenuItemDivCol10Button);
  newMenuItemDivCol10Button.appendChild(newMenuItemDivCol10ButtonSpan);
};

// Ulaşım Yolları ve Kat Düzeni Menülerine Item Ekleme
document.addEventListener("DOMContentLoaded", function () {
  // Ulaşım Yolları Menüsüne Item Ekleme
  const menu = document.getElementById("ulasimyollariMenu");
  const addMenuItemLoadButton = document.getElementById("addMenuItemLoad");

  addMenuItemLoadButton.addEventListener("click", function () {
    addMenuItem(
      menu,
      "ulasimyollariItem",
      "ulasimyollaritext",
      "ulasimyollariselect",
      [
        { value: "Sokak", text: "Sokak" },
        { value: "Caddesi", text: "Caddesi" },
        { value: "Bulvarı", text: "Bulvarı" },
      ],
      "col-52",
      "col-35",
      "Sokak/Cadde/Bulvar.."
    );
  });
});

// Ulaşm yolları ve kat düzeni verilerini çekme
function processElements(id, textSelector, selectSelector, separator) {
  let elements = document.querySelectorAll("#" + id);
  //console.log(`${id} Elements:`, elements);
  const dataList = [];

  for (let i = 0; i < elements.length; i++) {
    let TextValue = elements[i].querySelector(textSelector).value;
    let SelectValue = elements[i].querySelector(selectSelector).value;

    if (TextValue !== "") {
      if (SelectValue == "zemin kat") {
        dataList.push(`${SelectValue}`);
      } else {
        dataList.push(`${TextValue} ${SelectValue}`);
      }
      // dataList.push(`${TextValue} ${SelectValue}`);
    }
  }
  return dataList.join(separator);
};

// Altyapı verilerini çekme
function processCheckboxesElements(id) {
  let ele = document.getElementsByName(id);
  var checkedValue = null;
  const checked_list = [];
  for (var i = 0; ele[i]; i++) {
    if (ele[i].checked) {
      checkedValue = ele[i].value;
      checked_list.push(checkedValue);
    }
  }
  return checked_list.join(", ");
};

//BB bölümlerin verilerini çekme
// function processElements2(id) {
//   let ele = document.getElementsByName(id);
//   //console.log("bbbolumleriElements:", ele)
//   const selected_list = [];
//   for (var i = 0; ele[i]; i++) {
//     if (ele[i].checked) {
//       var selectEle = document.getElementById(ele[i].id + "-select");
//       //console.log("bbbolumleri_selects:", selectEle)
//       var checkedValue = ele[i].value;
//       var selectedValue = selectEle.value;
//       if (selectedValue === "1") {
//         selected_list.push(checkedValue);
//       } else {
//         selected_list.push(selectedValue + " " + checkedValue);
//       }
//     }
//   }
//   return selected_list.join(", ");
// };


function processElements2(id) {
  let ele = document.getElementsByName(id);
  const selected_list = [];

  for (var i = 0; ele[i]; i++) {
    if (ele[i].checked) {
      var selectEle = document.getElementById(ele[i].id + "-select");
      var inputEle = document.getElementById(ele[i].id + "-text"); // Manuel giriş kutusu

      var checkedValue = ele[i].value;
      var selectedValue = selectEle ? selectEle.value : "";
      var manualValue = inputEle ? inputEle.value.trim() : "";

      if (manualValue) {
        if (selectedValue === "1") {
          selected_list.push(manualValue + " " + checkedValue);
        } else {
          selected_list.push(selectedValue + " " + manualValue + " " + checkedValue);
        }
      } else {
        if (selectedValue === "1") {
          selected_list.push(checkedValue);
        } else {
          selected_list.push(selectedValue + " " + checkedValue);
        }
      }
    }
  }
  return selected_list.join(", ");
};



//bbBlok konum verilerini çekme
function processElements3(id) {
  let ele = document.getElementsByName(id);
  //console.log("bbbolumleriElements:", ele)
  const selected_list = [];
  for (var i = 0; ele[i]; i++) {
    if (ele[i].checked) {
      var selectEle = document.getElementById(ele[i].id + "-select");
      //console.log("bbbolumleri_selects:", selectEle)
      var checkedValue = ele[i].value;
      var selectedValue = selectEle.value;
      if (selectedValue === "1") {
        selected_list.push(checkedValue);
      } else {
        selected_list.push(selectedValue + " " + checkedValue);
      }
    }
  }
  return selected_list.join(", ");
};

function getRandomCharacter() {
  //const characters =  ['!', '#', '$', '%', '&', '(', ')', '*', '+', '=', '?', '/', '\\', '[', ']'];
  //const characters =  ['aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff', 'ggg', 'hhh', 'jjj', 'kkk', 'lll', 'mmm', 'nnn', 'ppp', 'rrr'];
  const characters = [
    "---",
    "###",
    "///",
    "+++",
    "(((",
    ")))",
    "***",
    "===",
    "--",
    "##",
    "//",
    "++",
    "((",
    "))",
    "**",
    "==",
  ];
  const randomCharacter =
    shuffle(characters)[Math.floor(Math.random() * characters.length)];
  //return randomCharacter;
  const randomColor = "red";
  return { character: randomCharacter, color: randomColor };
};

function run2() {
  const denemeElementtt = document.getElementById("textContainer");
  console.log(denemeElementtt);
  denemeElementtt.innerHTML = denemeElementtt.innerHTML.replaceAll("[{}]", "");
};

function getRandomColorr() {
  const letters = "0123456789ABCDEF";
  let color = "#";
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
};

function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
};

const colornames = [
  "skyblue",
  "antiquewhite",
  "cornflowerblue",
  "aqua",
  "cadetblue",
  "aquamarine",
  "cornsilk",
  "powderblue",
  "forestgreen",
  "lightskyblue",
  "lightgreen",
  "lightcyan",
  "lemonchiffon",
  "lightsteelblue",
  "lightblue",
  "aliceblue",
];

function getRandomColor() {
  const randomColor =
    shuffle(colornames)[Math.floor(Math.random() * colornames.length)];
  return randomColor;
};

function createColorGenerator(colors) {
  let index = 0;
  return function getNextColor() {
    if (index >= colors.length) {
      index = 0; // Reset to the first color if we've gone past the end
    }
    return colors[index++];
  };
};
const getColor = createColorGenerator(colornames);

function colorBox() {
  const colorBoxElements = document.getElementsByClassName("colorBox");
  const colorBoxArray = Array.from(colorBoxElements);
  //console.log("colorBoxArray", colorBoxArray)
  colorBoxArray.forEach((element) => {
    element.style.backgroundColor = getRandomColor();
    //element.style.backgroundColor = getColor();
  });
};

function petekKombi() {
  var BBisinmapetekElement = document.getElementById("bbpetekkombi");
  var BBpetekkombiSpanElement = document.querySelector(".bbpkSpan");
  var BBisinmaElement = document.getElementById("bbisinma");
  var BBisinmaValue =
    BBisinmaElement.options[BBisinmaElement.selectedIndex].textContent;
  console.log("BBpetekkombiSpanElement:", BBpetekkombiSpanElement);
  if (BBisinmaValue === "Doğalgazlı Kombi") {
    BBisinmapetekElement.style.display = "block";
    BBpetekkombiSpanElement.style.display = "inline-block";
  } else {
    BBisinmapetekElement.style.display = "none";
    BBpetekkombiSpanElement.style.display = "none";
  }
};

// BBzeminler ve BBduvarlar ********************************************************************************
let itemCounter = 0;
function addItem(menuType) {
  itemCounter++;
  //const randomColor = getRandomColor();
  const randomColor = getColor();
  const itemId = `${menuType}Item${itemCounter}`;
  const elementId = `${menuType}Element${itemCounter}`;
  const checkBoxClass = `myCheckbox_${menuType}${itemCounter}`;
  const selectedValuesId = `selectedValues_${menuType}${itemCounter}`;
  const menuId = `${menuType}${itemCounter}`;

  const itemTemplate = `    
        <div class="row" id="${itemId}" style="border:1px dashed #ccc; background-color: #f1f1f1;">
            <div class="col-20" id="${elementId}">
                <div class="dropdown">
                    <label type="button" class="dropbtnn" onclick="toggleDropdownClassName('myDropdownn_${menuType}${itemCounter}')" style="width:65px; background-color: ${randomColor};">Bölümler</label>
                    <div class="myDropdownn_${menuType}${itemCounter} dropdown-contentt" style="min-width: 400px; max-height: 360px; top:100%; background-color: ${randomColor};">
                      <div onclick="preventClose(event)">
                        <div class="col-50">
                            ${getCheckBoxTemplate1(checkBoxClass, menuType)}
                        </div>
                        <div class="col-50">
                            ${getCheckBoxTemplate2(checkBoxClass, menuType)}
                        </div>
                      </div>
                    </div>
                </div>
            </div>
            <div class="col-27" style="font-size:14px;">
                <p id="${selectedValuesId}" style="margin-top: 4px; padding-left:2px;"></p>
            </div>
            <div class="col-40">
                <select id="${menuId}" name="${menuType}" style="font-size:14px;padding-left: 6px;padding-right: 6px;" onchange="collectData()">
                    ${getOptionsTemplate(menuType)}
                </select>
            </div>
            <div class="col-10" style="margin:4px 0 0 3px;">
                <button type="button" onclick="deleteItem('${itemId}')">
                    <span class="material-symbols-outlined">delete</span>
                </button>
            </div>
            <div id="DataDisplay_${menuType}${itemCounter}" style="display:none;"></div>
        </div>  
        <div id="AllDataMain_${menuType}" style="display:none;"></div>     
    `;
  const container = document.getElementById(`${menuType}Menu`);
  container.insertAdjacentHTML("beforeend", itemTemplate);

  document.querySelector(`[name="row_${menuType}"]`).style.borderBottom =
    "2px solid violet";
};

function deleteItem(itemId) {
  const item = document.getElementById(itemId);
  item.remove();
};

function updateSelectedd(menuType, id) {
  const checkboxes = document.querySelectorAll(`.myCheckbox_${menuType}${id}`);
  const selected = [];
  checkboxes.forEach((checkbox) => {
    if (checkbox.checked) {
      selected.push(checkbox.value);
    }
  });

  const selectedValuesElement = document.getElementById(
    `selectedValues_${menuType}${id}`
  );
  if (selectedValuesElement) {
    selectedValuesElement.innerText = selected.length
      ? selected.join(", ")
      : "";
  }
};

function updateSelecteddd2(Item) {
  const checkboxes = document.querySelectorAll(`.myCheckbox_${Item}`);
  const selectedValElement = document.getElementById(`selectedValue-${Item}`);

  // // Seçilen checkbox'ları filtrele ve textContent'lerini al
  // const selected = Array.from(checkboxes)
  //     .filter(checkbox => checkbox.checked)
  //     .map(checkbox => checkbox.parentNode.textContent.trim());

  // Seçilen checkbox'ları filtrele, checkbox seçiliyse ve manuel giriş varsa, sadece manuel girişi kullan
  const selected = Array.from(checkboxes)
    .filter(
      (checkbox) =>
        checkbox.checked ||
        (checkbox.nextElementSibling &&
          checkbox.nextElementSibling.value.trim() !== "")
    )
    .map((checkbox) => {
      const manualInput = checkbox.nextElementSibling
        ? checkbox.nextElementSibling.value.trim()
        : "";
      if (checkbox.checked && manualInput !== "") {
        return manualInput; // Eğer checkbox seçiliyse ve manuel giriş varsa, sadece manuel girişi kullan
      }
      return checkbox.parentNode.textContent.trim(); // Checkbox seçili değilse veya manuel giriş yoksa label yaz
    });

  // Seçilenleri yazdır ve result'a  ata.
  selectedValElement.innerHTML = selected.join("<br>");
  result = selected.join("<br>");

  return result;
};

function updateSelecteddd(items) {
  let result = "";
  items.forEach((Item) => {
    const checkboxes = document.querySelectorAll(`.myCheckbox_${Item}`);
    const selected = [];

    checkboxes.forEach((checkbox) => {
      if (checkbox.checked) {
        selected.push(checkbox.value);
      }
    });

    const selectedValElement = document.getElementById(`selectedValue-${Item}`);
    if (selectedValElement) {
      selectedValElement.innerText = selected.length ? selected.join(", ") : "";
      result = selected.join(", ");
      resultLength = selected.length;
    } else {
      console.error(`Element with id selectedValue-${Item} not found.`);
      result = null;
    }
  });

  return [result, resultLength];
};

// function updateSelectedBanyo(items) {
//   let result = "";
//   items.forEach((Item) => {
//     const checkboxes = document.querySelectorAll(`.myCheckbox_${Item}`);
//     const selected = [];

//     checkboxes.forEach((checkbox) => {
//       if (checkbox.checked) {
//         selected.push(checkbox.value);
//       }
//     });

//     const selectedValElement = document.getElementById(`selectedValue-${Item}`);
//     if (selectedValElement) {
//       selectedValElement.innerText = selected.length ? selected.join(", ") : "";
//       result = "banyosunda " + selected.join(", ") + " bulunmaktadır";
//       resultLength = selected.length;
//     } else {
//       console.error(`Element with id selectedValue-${Item} not found.`);
//       result = null;
//     }
//   });

//   return [result, resultLength];
// };

function updateSelectedBanyo(items) {
  let result = "";
  let resultLength = 0;
  const kaplamaList = ["şap beton", "kaba beton", "seramik kaplama"];

  items.forEach((Item) => {
    const checkboxes = document.querySelectorAll(`.myCheckbox_${Item}`);
    const selected = [];

    checkboxes.forEach((checkbox) => {
      if (checkbox.checked) {
        selected.push(checkbox.value);
      }
    });

    const selectedValElement = document.getElementById(`selectedValue-${Item}`);
    if (selectedValElement) {
      selectedValElement.innerText = selected.length ? selected.join(", ") : "";
      resultLength = selected.length;

      if (selected.some(value => kaplamaList.includes(value))) {
        result = "banyosu " + selected.join(", ") + " kaplamadır";
      } else {
        result = "banyosunda " + selected.join(", ") + " bulunmaktadır";
      }
    } else {
      console.error(`Element with id selectedValue-${Item} not found.`);
      result = null;
    }
  });

  return [result, resultLength];
};


function updateSelectedFarklilik(items) {
  let result = "";
  items.forEach((Item) => {
    const checkboxes = document.querySelectorAll(`.myCheckbox_${Item}`);
    const selected = [];

    checkboxes.forEach((checkbox) => {
      if (checkbox.checked) {
        selected.push(checkbox.value);
      }
    });
    result = selected.join(", ");
  });

  return result;
};

// Eklentiler
function updateSelectedEklenti(eklentiType) {
  const checkboxes = document.querySelectorAll(
    `[class*="myCheckbox_${eklentiType}"]`
  );
  const valuesMap = {
    bbeklenti: {
      salonkartonpiyer: "",
      odasalonkartonpiyer: "",
      degerlemegunu: "",
    },
    imareklenti: {
      imareklentibelediyeicinde: "",
      imareklentibelediyedisinda: "",
      imareklentietkilememekte: "",
      imareklentietkilemekte: "",
      imareklentiresmibelgevar: "",
      imareklentiresmibelgeyok: "",
    },
  };

  if (!valuesMap.hasOwnProperty(eklentiType)) {
    console.error(`Unsupported eklentiType: ${eklentiType}`);
    return [];
  }

  const values = valuesMap[eklentiType];

  checkboxes.forEach((checkbox) => {
    if (checkbox.checked && values.hasOwnProperty(checkbox.value)) {
      values[checkbox.value] = document.getElementById(
        "checkboxLabel_" + checkbox.value
      ).textContent;
    }
  });

  return Object.values(values);
};

function getCheckBoxTemplate1(checkBoxClass, menuType) {
  //const sections = ["hol", "antre", "mutfak", "salon", "salon+mutfak", "oda", "soyunma odası", "kiler", "kış bahçesi", "banyo/wc", "banyo", "wc", "lavabo", "ebeveyn banyo", "duş", "balkon", "kapalı balkon", "ıslak hacimler", "diğer hacimler"];
  const sections = [
    "hol",
    "antre",
    "mutfak",
    "salon",
    "salon+mutfak",
    "oda",
    "soyunma odası",
    "kiler",
    "kış bahçesi",
    "depo",
  ];
  return sections
    .map(
      (section) =>
        `<label><input type="checkbox" class="${checkBoxClass}" value="${section}" onchange="updateSelectedd('${menuType}', ${itemCounter}); collectData()">${section.charAt(0).toUpperCase() + section.slice(1)
        }</label>`
    )
    .join("");
};

function getCheckBoxTemplate2(checkBoxClass, menuType) {
  const sections = [
    "banyo/wc",
    "banyo",
    "wc",
    "lavabo",
    "ebeveyn banyo",
    "duş",
    "balkon",
    "kapalı balkon",
    "ıslak hacimler",
    "diğer hacimler",
  ];
  return sections
    .map(
      (section) =>
        `<label><input type="checkbox" class="${checkBoxClass}" value="${section}" onchange="updateSelectedd('${menuType}', ${itemCounter}); collectData()">${section.charAt(0).toUpperCase() + section.slice(1)
        }</label>`
    )
    .join("");
};

function getOptionsTemplate(menuType) {
  if (menuType === "bbzeminler") {
    return `
            <option value="parke kaplamadır">Parke</option>
            <option value="laminat parke kaplama" selected>Laminat Parke</option>
            <option value="eski tip parke kaplama">Eski Tip Parke</option>
            <option value="seramik kaplama">Seramik</option>
            <option value="eski tip seramik kaplama">Eski Tip Seramik</option>
            <option value="mermer kaplama">Mermer</option>
            <option value="karotaş kaplama">Karotaş</option>
            <option value="beton kaplama">Beton</option>
            <option value="dökme beton kaplama">Dökme Beton</option>
            <option value="halıfleks kaplama">Halıflesk</option>
            <option value="şap beton kaplama">Şap Beton</option>
            <option value="kaba beton kaplama">Kaba Beton</option>
        `;
  } else if (menuType === "bbduvarlar") {
    return `
            <option value="plastik boyalı">Plastik Boyalı</option>
            <option value="saten boyalı">Saten Boyalı</option>
            <option value="fayans kaplama">Fayans Kaplama</option>
            <option value="fayans kaplama ve plastik boyalı">Fayans + Plastik Boyalı</option>
            <option value="duvar kağıdı kaplama">Duvar Kağıdı</option>
            <option value="ince sıvalı">İnce Sıvalı</option>
            <option value="kaba sıvalı">Kaba Sıvalı</option>
        `;
  }
};

function collectData() {
  const menuTypes = ["bbzeminler", "bbduvarlar"]; // Add more menu types if needed
  const AllDataPointElement = document.getElementById("AllDataPoint");

  const selectedAllDataMain = [];
  menuTypes.forEach((menuType) => {
    const allDataDisplayElement = document.getElementById(
      `AllDataMain_${menuType}`
    );
    const selectedDataDisplay = [];
    for (let i = 1; i <= itemCounter; i++) {
      const selectedValuesElement = document.getElementById(
        `selectedValues_${menuType}${i}`
      );
      const menuElement = document.getElementById(`${menuType}${i}`);
      const dataDisplayElement = document.getElementById(
        `DataDisplay_${menuType}${i}`
      );

      if (selectedValuesElement && menuElement && dataDisplayElement) {
        const selectedValues = selectedValuesElement.innerText;
        const selectedOption =
          menuElement.options[menuElement.selectedIndex].value;
        const selectedValuesItems = [selectedValues][0]
          .split(",")
          .map((item) => item.trim());
        console.log("selectedValuesItems", selectedValuesItems);
        const checkListString = ["ıslak hacimler", "diğer hacimler"];
        const hasAny = checkListString.some((item) =>
          selectedValuesItems.includes(item)
        );
        if (hasAny) {
          dataDisplayElement.textContent = `${selectedValues}de ${selectedOption}`;
        } else {
          if (selectedValuesItems.length == 1) {
            dataDisplayElement.textContent = `${selectedValues} bölümünde ${selectedOption}`;
          } else {
            dataDisplayElement.textContent = `${selectedValues} bölümlerinde ${selectedOption}`;
          }
        }
      }
    }
    const dataDisplayElements = document.querySelectorAll(
      `[id*="DataDisplay_${menuType}"]`
    );
    //console.log("dataDisplayElements", dataDisplayElements)
    dataDisplayElements.forEach((element) => {
      selectedDataDisplay.push(element.textContent);
    });
    //console.log("selectedDataDisplay", selectedDataDisplay)
    //console.log("selectedDataDisplay[0]", selectedDataDisplay[0])
    //allDataDisplayElement.textContent = selectedDataDisplay[0];
    // allDataDisplayElement.textContent = `${selectedDataDisplay.join(', ')}`;
    //allDataDisplayElement.textContent = (selectedDataDisplay == null ? `${selectedDataDisplay.join(', ')}` : "");
    if (`${selectedDataDisplay.join(", ")}`) {
      allDataDisplayElement.textContent = `${selectedDataDisplay.join(", ")}`;
    } else {
      console.error("Element not found");
    }
  });

  const allDataMainElements = document.querySelectorAll(`[id*="AllDataMain_"]`);
  //console.log("allDataMainElements", allDataMainElements)
  allDataMainElements.forEach((element) => {
    selectedAllDataMain.push(element.textContent);
  });
  //console.log("selectedAllDataMain", selectedAllDataMain)
  //AllDataPointElement.textContent = selectedAllDataMain.join(', ');
  let filteredselectedAllDataMain = selectedAllDataMain.filter(
    (item) => item !== ""
  );
  let Itemm = `Zeminler, ${filteredselectedAllDataMain[0]}dır. Duvarlar, ${filteredselectedAllDataMain[1]}dır.`;
  //console.log("Itemm", Itemm)
  AllDataPointElement.textContent = Itemm;
  return Itemm;
};

// ProjeMenu Ekleme **********************************************************************************
let itemCounter3 = 0;
function addItemProjeMenu() {
  // Get the original item to be cloned
  const originalItem = document.getElementById("projeItem");

  // Clone the item
  const newItem = originalItem.cloneNode(true);

  // Increment the item counter to ensure unique IDs
  itemCounter3++;

  // Update the ID of the cloned item and its children to avoid duplicate IDs
  newItem.id = `projeItem-${itemCounter3}`;
  newItem.querySelector("#projeselect1").id = `projeselect1-${itemCounter3}`;
  newItem.querySelector("#projeselect2").id = `projeselect2-${itemCounter3}`;
  newItem.querySelector("#projeDate").id = `projeDate-${itemCounter3}`;
  newItem.querySelector(
    "#deleteItemProjeMenu"
  ).id = `deleteItemProjeMenu-${itemCounter3}`;

  // Remove tooltip from the previous projeItem if it exists
  const previousItem = document.getElementById(`projeItem-${itemCounter3 - 1}`);
  if (previousItem) {
    const existingTooltip = previousItem.querySelector(".tooltip");
    if (existingTooltip) {
      existingTooltip.remove();
    }
  }

  // Create a new tooltip for the new item
  const tooltip = document.createElement('div');
  tooltip.id = `tooltip-${itemCounter3}`;
  tooltip.classList.add('tooltip');
  tooltip.classList.add('col-100');
  tooltip.style.display = 'none';
  tooltip.style.textAlign = 'right';
  tooltip.textContent = 'Lütfen tarih seçin';

  // Append the tooltip to the new item
  newItem.appendChild(tooltip);

  // Set the style of the new item to be visible
  newItem.style.display = "block";

  // Ensure that the selected option remains the same in the cloned item
  const originalSelect1 = originalItem.querySelector("#projeselect1");
  const originalSelect2 = originalItem.querySelector("#projeselect2");
  const clonedSelect1 = newItem.querySelector(`#projeselect1-${itemCounter3}`);
  const clonedSelect2 = newItem.querySelector(`#projeselect2-${itemCounter3}`);
  clonedSelect1.value = originalSelect1.value;
  clonedSelect2.value = originalSelect2.value;

  // Reset the values of inputs within the cloned item
  newItem.querySelector(`#projeDate-${itemCounter3}`).value = "";

  // Append the new item to the container
  document.getElementById("projeMenu").appendChild(newItem);

  // Add event listener to the delete button of the newly created item
  newItem
    .querySelector(`#deleteItemProjeMenu-${itemCounter3}`)
    .addEventListener("click", function () {
      newItem.remove();
    });

  // Add tooltip functionality to the newly added input (projeDate)  
  attachTooltip(`#projeDate-${itemCounter3}`, `#tooltip-${itemCounter3}`, "Bila tarihi için 11.11.1111 giriniz.");
};

function attachTooltip(inputSelector, tooltipSelector, message) {
  const inputs = document.querySelectorAll(inputSelector);
  const tooltip = document.querySelector(tooltipSelector);

  if (!tooltip) {
    console.error("Tooltip elementi bulunamadı.");
    return;
  }

  // Tooltip içeriğini ayarla
  tooltip.textContent = message;

  inputs.forEach(input => {
    input.addEventListener("mouseover", () => {
      const rect = input.getBoundingClientRect();
      // ID ile parent öğeyi seçmek
      const parentRect = document.getElementById(input.closest('[id^="projeItem"]').id).getBoundingClientRect();
      //const parentRect = input.closest(".projeItem").getBoundingClientRect(); // parent item width
      tooltip.style.left = `${parentRect.left + window.scrollX}px`;
      tooltip.style.top = `${rect.top + window.scrollY - tooltip.offsetHeight - 10}px`;
      tooltip.style.width = `${parentRect.width}px`; // Tooltip genişliğini parent item ile aynı yap
      tooltip.style.display = "block";
    });

    // input.addEventListener("mouseout", () => {
    //   tooltip.style.display = "none";
    // });
  });
};

// ProjeRuhsatİskanMenu Ekleme **********************************************************************************
let itemCounter2 = 0;
function addItemRuhsatIskanMenu() {
  // Get the original item to be cloned
  const originalItem = document.getElementById("projeRuhsatIskanItem");

  // Clone the item
  const newItem = originalItem.cloneNode(true);

  // Increment the item counter to ensure unique IDs
  itemCounter2++;

  // Update the ID of the cloned item and its children to avoid duplicate IDs
  newItem.id = `projeRuhsatIskanItem-${itemCounter2}`;
  newItem.querySelector(
    "#projeRuhsatIskanselect"
  ).id = `projeRuhsatIskanselect-${itemCounter2}`;
  newItem.querySelector(
    "#projeRuhsatIskanDate"
  ).id = `projeRuhsatIskanDate-${itemCounter2}`;
  newItem.querySelector(
    "#projeRuhsatIskantext"
  ).id = `projeRuhsatIskantext-${itemCounter2}`;
  newItem.querySelector(
    "#deleteItemprojeRuhsatIskanMenu"
  ).id = `deleteItemprojeRuhsatIskanMenu-${itemCounter2}`;

  // Set the style of the new item to be visible
  newItem.style.display = "block";

  // Ensure that the selected option remains the same in the cloned item
  const originalSelect = originalItem.querySelector("#projeRuhsatIskanselect");
  const clonedSelect = newItem.querySelector(
    `#projeRuhsatIskanselect-${itemCounter2}`
  );
  clonedSelect.value = originalSelect.value;

  // Reset the values of inputs within the cloned item
  //   newItem.querySelector(`#projeRuhsatIskanselect-${itemCounter2}`).value = '';
  newItem.querySelector(`#projeRuhsatIskanDate-${itemCounter2}`).value = "";
  newItem.querySelector(`#projeRuhsatIskantext-${itemCounter2}`).value = "";

  // Append the new item to the container
  document.getElementById("projeRuhsatIskanMenu").appendChild(newItem);

  // Add event listener to the delete button of the newly created item
  newItem
    .querySelector(`#deleteItemprojeRuhsatIskanMenu-${itemCounter2}`)
    .addEventListener("click", function () {
      newItem.remove();
    });
};

// KaticerigiMenu ve AltMenu Ekleme **********************************************************************************
let itemCount = 0;
function addItemKaticerigiMenu() {
  itemCount++;
  const itemTemplateKaticerigiMenu = `
        <div class="row menu_border" id="katicerigiItem-${itemCount}">
            <div class="row">
                <div class="row">
                    <div class="col-10" style="margin:4px 0 0 2px;">
                        <button type="button" id="addMenuItemLoad3" onclick="deleteItemKaticerigiMenu(${itemCount}); updateAllMenuText()[0];">
                            <span class="material-symbols-outlined">
                                delete
                            </span>
                        </button>
                    </div>
                    <div class="col-20">
                        <select id="katicerigiselect1-${itemCount}" name="katicerigiselect1" style="padding-left: 6px; color:red;" onchange="updateMenuText(${itemCount}); updateAllMenuText()[0]">
                            ${[...Array(20).keys()]
      .map(
        (i) =>
          `<option value="${i + 1}.">${i + 1}.</option>`
      )
      .join("")}
                        </select>
                    </div>
                    <div class="col-45">
                        <select id="katicerigiselect2-${itemCount}" name="katicerigiselect2" style="color:red" onchange="updateMenuText(${itemCount}); updateAllMenuText()[0]">
                            <option value="bodrum kat">Bodrum Kat</option>
                            <option value="zemin kat">Zemin Kat</option>
                            <option value="normal kat" selected>Normal Kat</option>
                            <option value="çatı kat">Çatı Kat</option>
                            <option value="teras kat">Teras Kat</option>
                            <option value="asma kat">Asma Kat</option>
                        </select>
                    </div>
                    <div class="col-15">
                        <label type="button" class="label_button" style="width:100px; height:41px; margin-left:2px;" onclick="addItemKaticerigiAltmenu(${itemCount})">Alt Menü Ekle</label>
                    </div>
                </div>
                <div class="row" id="katiçerigiAltMenu-${itemCount}"></div>
            </div>            
        </div>
        <div class="row MenuText" id="MenuText-${itemCount}" style="display:none; margin-top:8px; padding: 0 4px;"></div>
        <div class="row MenuText2" id="MenuText2-${itemCount}" style="display:none; margin-top:8px; padding: 0 4px;"></div>

    `;
  const containerKaticerigiMenu = document.getElementById("katicerigiMenu");
  containerKaticerigiMenu.insertAdjacentHTML(
    "beforeend",
    itemTemplateKaticerigiMenu
  );
};

function addItemKaticerigiAltmenu(menuId) {
  itemCount++;
  const randomColor = getColor();
  const containerKaticerigiAltmenu = document.getElementById(
    `katiçerigiAltMenu-${menuId}`
  );
  if (!containerKaticerigiAltmenu) {
    console.error(`Element with id katiçerigiAltMenu-${menuId} not found`);
    return;
  }

  const dropdown = `    
        <div class="dropdown">
            <label type="button" onclick="toggleDropdown(${menuId}, ${itemCount})" class="label_button" style="width:100px; height: 41px; background-color: ${randomColor};">BBNO Seç</label>
            <div class="dropdown-content dropdown-content-${menuId}-${itemCount}" style="background-color: ${randomColor};">
                ${[...Array(99).keys()]
      .map(
        (i) =>
          `<label><input type="checkbox" class="myCheckbox" value="${i + 1
          }" onchange="updateSelected(${menuId}, ${itemCount}); addClass(${menuId}, ${itemCount})"> ${i + 1
          }</label>`
      )
      .join("")}
            </div>
        </div>
    `;

  const itemTemplateKaticerigiAltmenu = `
        <div class="row" id="katiçerigiAltItem-${menuId}-${itemCount}">
            <div class="col-10x">
                <p style="color:#F1F1F1"></p>
            </div>
            <div class="col-90" style="border:1px dashed #ccc;">
                <div class="row">
                    <div class="col-25">
                        <select id="katicerigiselect3-${menuId}-${itemCount}" name="katicerigiselect3-${menuId}-${itemCount}" onchange="changeDisplay(${menuId}, ${itemCount}); addClass(${menuId}, ${itemCount})">
                            <option value="mesken">Mesken</option>
                            <option value="dukkan">Dükkan</option>
                            <option value="diger">Diğer</option>
                            <option value="dubleksnormal">Dubleks Mesken Normal Katı</option>
                            <option value="dubleksust">Dubleks Mesken Üst Katı</option>
                            <option value="dubleksalt">Dubleks Mesken Alt Katı</option>
                            <option value="dukkandepo">Çok Katlı Dükkan Deposu</option>
                            <option value="dukkanbodrum">Çok Katlı Dükkan Bodrum Katı</option>
                            <option value="dukkanzemin">Çok Katlı Dükkan Zemin Katı</option>
                            <option value="dukkanbatar">Çok Katlı Dükkan Batar Katı</option>
                            <option value="dukkannormal">Çok Katlı Dükkan Normal Katı</option>
                        </select>
                    </div>
                    <div class="col-25" id="meskenElement-${menuId}-${itemCount}" style="display: block;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkanElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="digerElement-${menuId}-${itemCount}" style="display: none;">
                        <div class="dropdown">
                            <label type="button" onclick="toggleDropdown(${menuId}, ${itemCount})" class="label_button" style="width: 100px; background-color: ${randomColor};">Diğer</label>
                            <div class="dropdown-content dropdown-content-${menuId}-${itemCount}" style="background-color: ${randomColor};">
                                ${[
      "bina girişi",
      "blok girişi",
      "otopark alanı",
      "depo",
      "kömürlükler",
      "kapıcı dairesi",
      "jimlastik salonu",
      "jeneratör odası",
      "hidrofor odası",
      "kalorifer dairesi",
      "kazan dairesi",
      "sığınak",
      "makina dairesi",
      "teras",
      "merdiven kovası",
    ]
      .sort()
      .map(
        (value) =>
          `<label><input type="checkbox" class="myCheckbox" value="${value}" onchange="updateSelected(${menuId}, ${itemCount})"> ${value}</label>`
      )
      .join("")}
                            </div>
                        </div>
                    </div>
                    <div class="col-25" id="dubleksnormalElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dubleksustElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dubleksaltElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkandepoElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkanbodrumElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkanzeminElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkanbatarElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>
                    <div class="col-25" id="dukkannormalElement-${menuId}-${itemCount}" style="display: none;">
                        ${dropdown}
                    </div>   
                    <div class="col-39" style="font-size:14px;">
                        <p id="selectedValues-${menuId}-${itemCount}" style="padding-left:10px;"></p>
                    </div>
                    <div class="col-10" style="margin:4px 1px 0 0;">
                        <button type="button" id="deleteAltMenuItemLoad" onclick="deleteItemKaticerigiAltmenu(${menuId}, ${itemCount}); updateAllMenuText()[0]">
                            <span class="material-symbols-outlined">
                                delete
                            </span>
                        </button>
                    </div>
                </div>
                <div class="row" id="altMenuText-${menuId}-${itemCount}" style="display:none;"></div>
                <div class="row" id="altMenuText2-${menuId}-${itemCount}" style="display:none;"></div>
            </div>
        </div>
    `;

  containerKaticerigiAltmenu.insertAdjacentHTML(
    "beforeend",
    itemTemplateKaticerigiAltmenu
  );
};

function deleteItemKaticerigiAltmenu(menuId, id) {
  const item = document.getElementById(`katiçerigiAltItem-${menuId}-${id}`);
  item.remove();
  updateMenuText(menuId);
};

function updateSelected(menuId, id) {
  const checkboxes = document.querySelectorAll(
    `.dropdown-content-${menuId}-${id} input[type="checkbox"]`
  );
  const selected = [];
  checkboxes.forEach((checkbox) => {
    if (checkbox.checked) {
      selected.push(checkbox.value);
    }
  });
  const selectedValuesElement = document.getElementById(
    `selectedValues-${menuId}-${id}`
  );
  if (selectedValuesElement) {
    selectedValuesElement.innerText = selected.length
      ? selected.join(", ")
      : "";
  }

  updateAltMenuText(menuId, id, selected);
  updateMenuText(menuId);
  updateAllMenuText(menuId);
};

function toggleDropdown(menuId, id) {
  document
    .querySelector(`.dropdown-content-${menuId}-${id}`)
    .classList.toggle("show");
};

function toggleDropdownClassName(className) {
  document.querySelector(`.${className}`).classList.toggle("show");
};

function preventClose(event) {
  event.stopPropagation();
};

function changeDisplay3(id, labelElement) {
  const DivElement = document.getElementById(id);
  const isHidden = DivElement.style.display === "none";

  DivElement.style.display = isHidden ? "block" : "none";
  labelElement.textContent = isHidden ? "Gizle" : "Göster";
}

function changeDisplay2() {
  // dubleks mi elemanları
  const select_dubleksmi = document.getElementById("dubleksmi");

  const bbalaniElement = document.getElementById("bbalaniDiv");
  const bbbolumleriDivElement = document.getElementById("bbbolumleriDiv");

  const dubleksaltkatElement = document.getElementById("dubleksaltkatDiv");
  const bbbolumlerDubleksAltKatDivElement = document.getElementById("bbbolumlerDubleksAltKatDiv");

  const dubleksnormalkatElement = document.getElementById("dubleksnormalkatDiv");
  const bbbolumlerDubleksNormalKatDivElement = document.getElementById("bbbolumlerDubleksNormalKatDiv");

  const dubleksustkatElement = document.getElementById("dubleksustkatDiv");
  const bbbolumlerDubleksUstKatDivElement = document.getElementById("bbbolumlerDubleksUstKatDiv");

  // takbisFarklılık elemanları
  const select_takbisFarklilikVarYok = document.getElementById("takbisFarklilikSelectVarYok");
  const takbisFarklilikVarElement = document.getElementById("takbisFarklilikVar");
  const takbisFarklilikSecElement = document.getElementById("takbisFarklilikSec");
  const FarklilikSecDivElement = document.getElementById("FarklilikSecDiv");

  // analiz ve sonucların değerlendirmesi elemanları
  const select_analizVeSonuclar = document.getElementById("analizVeSonuclarSelect");
  const sonucSatilabilirElement = document.getElementById("sonucSatilabilirDiv");
  const select_standartDegerTakdiri = document.getElementById("degerTakdiriSelect");
  const standartDegerTakdiriElement = document.getElementById("standartDegerTakdiriDiv");

  // yapı denetim elemanları
  const select_yapidenetim = document.getElementById("yapidenetimselect");
  const tabiiIskanYokElement = document.getElementById("tabiiIskanYok");

  // yapı denetim firma fesih elemanları
  const select_fesih = document.getElementById("fesihselect");
  const fesihTarihiElement = document.getElementById("fesihTarihi");

  // olumsuz belge elemanları
  const select_olumsuzbelge = document.getElementById("bbolumsuzbelgeselect");
  const bbolumsuzbelgedivElement = document.getElementById("bbolumsuzbelgediv");

  // aykırılık elemanları
  const select_aykirilik = document.getElementById("bbaykiriliklarselect");
  const bbaykiriliklardivElement = document.getElementById("bbaykiriliklardiv");

  // bbKonutTespiti elemanları
  const select_bb = document.getElementById("bbKonutTespiti");
  const bbyapilamiyorElement = document.getElementById(
    "bbkonumTespitiYapilamiyor"
  );

  // blokKonutTespiti elemanları
  const select_blok = document.getElementById("blokKonutTespiti");
  const yapiliyorElement = document.getElementById("konumTespitiYapiliyor");
  const yapilamiyorElement = document.getElementById("konumTespitiYapilamiyor");

  // satış kanaati elemanları
  const select_satisKanaati = document.getElementById("satisKanaatiSelect");
  const satilabilirElement = document.getElementById("kanaatSatilabilirDiv");
  const hisseliElement = document.getElementById("kanaatHisseliDiv");
  const aliciAzElement = document.getElementById("kanaatAlicisiAzDiv");
  const satisiZorElement = document.getElementById("kanaatSatisiZorDiv");
  const satilamazElement = document.getElementById("kanaatSatilamazDiv");
  const insSeviyeliElement = document.getElementById("kanaatInsSeviyeliDiv");

  // Site Özellikleri elemanları
  const select_sitedemi = document.getElementById("sitedemi");
  const siteozellikDivElement = document.getElementById("siteozellikDiv");

  /* ********************************************************************** */

  // dubleks mi durumunu kontrol et 
  if (select_dubleksmi) {
    if (select_dubleksmi.value === "hayır") {
      bbalaniElement.style.display = "block";
      bbbolumleriDivElement.style.display = "none";
      dubleksaltkatElement.style.display = "none";
      bbbolumlerDubleksAltKatDivElement.style.display = "none";
      dubleksnormalkatElement.style.display = "none";
      bbbolumlerDubleksNormalKatDivElement.style.display = "none";
      dubleksustkatElement.style.display = "none";
      bbbolumlerDubleksUstKatDivElement.style.display = "none";

    } else if (select_dubleksmi.value === "dubleks") {
      bbalaniElement.style.display = "none";
      bbbolumleriDivElement.style.display = "none";
      dubleksaltkatElement.style.display = "none";
      bbbolumlerDubleksAltKatDivElement.style.display = "none";
      dubleksnormalkatElement.style.display = "block";
      bbbolumlerDubleksNormalKatDivElement.style.display = "none";
      dubleksustkatElement.style.display = "block";
      bbbolumlerDubleksUstKatDivElement.style.display = "none";

    } else if (select_dubleksmi.value === "tersdubleks") {
      bbalaniElement.style.display = "none";
      bbbolumleriDivElement.style.display = "none";
      dubleksaltkatElement.style.display = "block";
      bbbolumlerDubleksAltKatDivElement.style.display = "none";
      dubleksnormalkatElement.style.display = "block";
      bbbolumlerDubleksNormalKatDivElement.style.display = "none";
      dubleksustkatElement.style.display = "none";
      bbbolumlerDubleksUstKatDivElement.style.display = "none";
    }
  };

  // takbisFarklılık durumunu kontrol et
  if (select_takbisFarklilikVarYok) {
    takbisFarklilikVarElement.style.display =
      select_takbisFarklilikVarYok.value === "var" ? "block" : "none";
    takbisFarklilikSecElement.style.display =
      select_takbisFarklilikVarYok.value === "var" ? "block" : "none";
    // FarklilikSecDivElement.style.display =
    // select_takbisFarklilikVarYok.value === "var" ? "block" : "none";
  };

  // analiz ve sonucların değerlendirmesi durumunu kontrol et
  if (select_analizVeSonuclar) {
    sonucSatilabilirElement.style.display =
      select_analizVeSonuclar.value === "sonucSatilabilir" ? "block" : "none";
  };

  // değer takdiridurumunu kontrol et
  if (select_standartDegerTakdiri) {
    standartDegerTakdiriElement.style.display =
      select_standartDegerTakdiri.value === "standartDegerTakdiri" ? "block" : "none";
  };

  // yapı denetim durumunu kontrol et
  if (select_yapidenetim) {
    tabiiIskanYokElement.style.display =
      select_yapidenetim.value === "yapidenetimIskanyok" ? "block" : "none";
  };

  // yapı denetim firma fesih durumunu kontrol et
  if (select_fesih) {
    fesihTarihiElement.style.display =
      select_fesih.value === "var" ? "block" : "none";
  };

  // olumsuz belge durumunu kontrol et
  if (select_olumsuzbelge) {
    bbolumsuzbelgedivElement.style.display =
      select_olumsuzbelge.value === "var" ? "block" : "none";
  };

  // aykırılık durumunu kontrol et
  if (select_aykirilik) {
    bbaykiriliklardivElement.style.display =
      select_aykirilik.value === "var" ? "block" : "none";
  };

  // bbKonutTespiti durumunu kontrol et
  if (select_bb) {
    bbyapilamiyorElement.style.display =
      select_bb.value === "yapilamiyor" ? "block" : "none";
    //console.log("bbKonumTespitiElement:", select_bb.value);
    //console.log("bbyapilamiyorElement:", bbyapilamiyorElement.value);
  };

  // blokKonutTespiti durumunu kontrol et
  if (select_blok) {
    const elementsss = {
      yapiliyor: yapiliyorElement,
      yapilamiyor: yapilamiyorElement,
    };

    for (let key in elementsss) {
      elementsss[key].style.display =
        select_blok.value === key ? "block" : "none";
    }
  };

  // satış kanaati durumunu kontrol et
  if (select_satisKanaati) {
    const elements = {
      kanaatSatilabilir: satilabilirElement,
      kanaatHisseli: hisseliElement,
      kanaatAlicisiAz: aliciAzElement,
      kanaatSatisiZor: satisiZorElement,
      kanaatSatilamaz: satilamazElement,
      kanaatInsSeviyeli: insSeviyeliElement,
    };
    for (let key in elements) {
      elements[key].style.display =
        select_satisKanaati.value === key ? "block" : "none";
    }
  };

  // Site Özellikleri durumunu kontrol et
  if (select_sitedemi) {
    siteozellikDivElement.style.display =
      select_sitedemi.value === "evet" ? "block" : "none";
    document.querySelectorAll(".siteparagraf").forEach((ele) => { ele.style.display = select_sitedemi.value === "evet" ? "inline" : "none"; });
  };
};

function changeDisplay(menuId, id) {
  const select = document.getElementById(`katicerigiselect3-${menuId}-${id}`);
  const meskenElement = document.getElementById(
    `meskenElement-${menuId}-${id}`
  );
  const dukkanElement = document.getElementById(
    `dukkanElement-${menuId}-${id}`
  );
  const digerElement = document.getElementById(`digerElement-${menuId}-${id}`);
  const dubleksnormalElement = document.getElementById(
    `dubleksnormalElement-${menuId}-${id}`
  );
  const dubleksustElement = document.getElementById(
    `dubleksustElement-${menuId}-${id}`
  );
  const dubleksaltElement = document.getElementById(
    `dubleksaltElement-${menuId}-${id}`
  );
  const dukkandepoElement = document.getElementById(
    `dukkandepoElement-${menuId}-${id}`
  );
  const dukkanbodrumElement = document.getElementById(
    `dukkanbodrumElement-${menuId}-${id}`
  );
  const dukkanzeminElement = document.getElementById(
    `dukkanzeminElement-${menuId}-${id}`
  );
  const dukkanbatarElement = document.getElementById(
    `dukkanbatarElement-${menuId}-${id}`
  );
  const dukkannormalElement = document.getElementById(
    `dukkannormalElement-${menuId}-${id}`
  );
  const selectedValuesElement = document.getElementById(
    `selectedValues-${menuId}-${id}`
  );
  const altMenuTextElement = document.getElementById(
    `altMenuText-${menuId}-${id}`
  );
  const altMenuText2Element = document.getElementById(
    `altMenuText2-${menuId}-${id}`
  );
  const checkboxesElements = document.querySelectorAll(
    `.dropdown-content-${menuId}-${id} .myCheckbox`
  );

  const elementss = {
    mesken: meskenElement,
    dukkan: dukkanElement,
    diger: digerElement,
    dubleksnormal: dubleksnormalElement,
    dubleksust: dubleksustElement,
    dubleksalt: dubleksaltElement,
    dukkandepo: dukkandepoElement,
    dukkanbodrum: dukkanbodrumElement,
    dukkanzemin: dukkanzeminElement,
    dukkanbatar: dukkanbatarElement,
    dukkannormal: dukkannormalElement,
  };

  for (let key in elementss) {
    //console.log("elementss[key]", elementss[key])
    elementss[key].style.display = select.value === key ? "block" : "none";
  }

  selectedValuesElement.textContent = "";
  altMenuTextElement.textContent = "";
  altMenuText2Element.textContent = "";

  checkboxesElements.forEach((checkbox) => {
    checkbox.checked = false;
  });

  updateMenuText(menuId);
};

function updateAltMenuText(menuId, id, selectedCheckboxes) {
  const selectElement = document.getElementById(
    `katicerigiselect3-${menuId}-${id}`
  );
  const selectkatElement = document.getElementById(
    `katicerigiselect1-${menuId}`
  );
  //console.log("selectkatElement", selectkatElement)
  const altMenuTextElement = document.getElementById(
    `altMenuText-${menuId}-${id}`
  );
  const altMenuText2Element = document.getElementById(
    `altMenuText2-${menuId}-${id}`
  );

  if (selectElement.value === "mesken") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu meskenler`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbMesken1 = selectedCheckboxes.length
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu mesken`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbMesken2 = selectedCheckboxes.length
    }
  } else if (selectElement.value === "dukkan") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanlar`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbDukkan1 = selectedCheckboxes.length
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkan`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbDukkan2 = selectedCheckboxes.length
    }
  } else if (selectElement.value === "diger") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    altMenuTextElement.textContent = `${selectedCheckboxesText}`;
  } else if (selectElement.value === "dubleksnormal") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenlerin normal katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      var bbMesken3 = selectedCheckboxes.length;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenin normal katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      var bbMesken4 = selectedCheckboxes.length;
    }
  } else if (selectElement.value === "dubleksust") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenlerin üst katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenin üst katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dubleksalt") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenlerin alt katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dubleks meskenin alt katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dukkandepo") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanlara ait depolar`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkana ait depo`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dukkanbodrum") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanların bodrum katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanın bodrum katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dukkanbatar") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanların batar katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanın batar katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dukkanzemin") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanların zemin katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanın zemin katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
    }
  } else if (selectElement.value === "dukkannormal") {
    const selectedCheckboxesText = selectedCheckboxes.join(", ");
    if (selectedCheckboxes.length > 1) {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanların ${selectkatElement.value}normal katları`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbDukkan3 = selectedCheckboxes.length
    } else {
      altMenuTextElement.textContent = `${selectedCheckboxesText} bağımsız bölüm no.lu dükkanın ${selectkatElement.value}normal katı`;
      altMenuText2Element.textContent = `${selectedCheckboxesText}`;
      //var bbDukkan4 = selectedCheckboxes.length
    }
  }
};

function BBCount() {
  const selectors = [".mesken", ".dubleksnormal", ".dukkan", ".dukkanzemin"];
  const [selectedMesken1, selectedMesken2, selectedDukkan1, selectedDukkan2] =
    selectors.map((selector) =>
      [...document.querySelectorAll(selector)].map(
        (element) => element.textContent
      )
    );

  const countItems = (arr) =>
    arr.reduce((count, item) => count + item.split(",").length, 0);

  const countMesken1 = countItems(selectedMesken1);
  const countMesken2 = countItems(selectedMesken2);
  const countDukkan1 = countItems(selectedDukkan1);
  const countDukkan2 = countItems(selectedDukkan2);

  const meskenCount = countMesken1 + countMesken2;
  const dukkanCount = countDukkan1 + countDukkan2;
  const BBCount = meskenCount + dukkanCount;

  //console.log("meskenCount", meskenCount);
  //console.log("dukkanCount", dukkanCount);
  //console.log("BBCount", BBCount);

  let TextBBCount = "";
  if (meskenCount > 0 && dukkanCount > 0) {
    TextBBCount = `${BBCount} adet bağımsız bölüm (${meskenCount} adet mesken, ${dukkanCount} adet dükkan)`;
  } else if (dukkanCount === 0) {
    TextBBCount = `${BBCount} adet bağımsız bölüm (${meskenCount} adet mesken)`;
  } else if (meskenCount === 0) {
    TextBBCount = `${BBCount} adet bağımsız bölüm (${dukkanCount} adet dükkan)`;
  }

  return [TextBBCount, BBCount];
};

function updateMenuText(menuId) {
  // Kat türlerini kontrol eden fonksiyon
  const select1Element = document.getElementById(`katicerigiselect1-${menuId}`);
  const select2Element = document.getElementById(`katicerigiselect2-${menuId}`);
  const altMenuTextElements = document.querySelectorAll(
    `[id*="altMenuText-${menuId}"]`
  );
  const altMenuText2Elements = document.querySelectorAll(
    `[id*="altMenuText2-${menuId}"]`
  );
  const MenuTextElement = document.getElementById(`MenuText-${menuId}`);
  const MenuText2Element = document.getElementById(`MenuText2-${menuId}`);
  const selected = [];
  const selected2 = [];

  altMenuTextElements.forEach((element) => {
    selected.push(element.textContent);
  });

  if (["zemin kat", "teras kat", "asma kat"].includes(select2Element.value)) {
    MenuTextElement.textContent = `${select2Element.value}ta ${selected.join(
      ", "
    )}`;
  } else if (["çatı kat"].includes(select2Element.value)) {
    MenuTextElement.textContent = `${select2Element.value}ında ${selected.join(
      ", "
    )}`;
  } else {
    MenuTextElement.textContent = `${select1Element.value} ${select2Element.value
      }ta ${selected.join(", ")}`;
  }

  altMenuText2Elements.forEach((element) => {
    selected2.push(element.textContent);
  });

  if (["zemin kat", "teras kat", "asma kat"].includes(select2Element.value)) {
    MenuText2Element.textContent = `${selected2.join(", ")}`;
  } else if (["çatı kat"].includes(select2Element.value)) {
    MenuText2Element.textContent = `${selected2.join(", ")}`;
  } else {
    MenuText2Element.textContent = `${selected2.join(", ")}`;
  }
};

function katSayilariniBul(katlar) {
  // Başlangıç değerleri
  const katSayilari = {
    bodrum: 0,
    zemin: 0,
    normal: 0,
    teras: 0,
    asma: 0,
    çatı: 0,
  };

  katlar.forEach(kat => {
    if (kat.includes('bodrum kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.bodrum = match ? parseInt(match[0]) : 0;
    } else if (kat.includes('zemin kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.zemin = match ? parseInt(match[0]) : 0;
    } else if (kat.includes('normal kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.normal = match ? parseInt(match[0]) : 0;
    } else if (kat.includes('teras kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.çatı = match ? parseInt(match[0]) : 0;
    } else if (kat.includes('asma kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.çatı = match ? parseInt(match[0]) : 0;
    }
    else if (kat.includes('çatı kat')) {
      const match = kat.match(/^\d+/);
      katSayilari.çatı = match ? parseInt(match[0]) : 0;
    }
  });

  return katSayilari;
};

function updateAllMenuText(menuId) {
  const MenuTextElements = document.querySelectorAll(`.MenuText`);
  const MenuText2Elements = document.querySelectorAll(`.MenuText2`);
  //const MenuTextElements = document.querySelectorAll(`#MenuText-${menuId}`);
  // const MenuTextElements = document.querySelectorAll(`[id*="MenuText-${menuId}"]`);
  // const MenuText2Elements = document.querySelectorAll(`[id*="MenuText2-${menuId}"]`);
  //console.log("MenuTextElements", MenuTextElements)
  //console.log("MenuText2Elements", MenuText2Elements)
  const AllMenuTextElement = document.getElementById(`AllMenuText`);
  const AllMenuText2Element = document.getElementById(`AllMenuText2`);
  const selected = [];
  const selected2 = [];
  const selected_kat = [];

  //MenuTextElements
  MenuTextElements.forEach((element) => {
    selected.push(element.textContent);
    // console.log("selected", selected);
  });
  AllMenuTextElement.textContent = selected.join(", ");
  //console.log("AllMenuTextElement", selected)

  //MenuText2Elements
  MenuText2Elements.forEach((element) => {
    selected2.push(element.textContent);
    // console.log("selected2", selected2);
  });
  AllMenuText2Element.textContent = selected2.join(", ");

  const katIsimleri = {
    bodrumKat: "bodrum kat",
    zeminKat: "zemin kat",
    normalKat: "normal kat",
    terasKat: "teras kat",
    asmaKat: "asma kat",
    catiKat: "çatı kat",
  };

  // console.log("katSayisiniBul", katSayisiniBul(selected))

  for (let [key, value] of Object.entries(katSayisiniBul(selected))) {
    if (value !== 0) {
      selected_kat.push(`${value} ${katIsimleri[key]}`);
    }
  }
  // console.log("selected_kat:", selected_kat)
  // console.log("selected_katJO:", selected_kat.join(' + '))
  // console.log("katSayisiniBul2:", katSayisiniBul2(selected_kat))

  const sonucKatSayisi = katSayilariniBul(selected_kat);
  // console.log("sonucKatSayisi", sonucKatSayisi);

  kotAltiSayisi = sonucKatSayisi.bodrum
  kotUstuSayisi = sonucKatSayisi.zemin + sonucKatSayisi.normal + sonucKatSayisi.asma
  // console.log("kotAltiSayisi", kotAltiSayisi);
  // console.log("kotUstuSayisi", kotUstuSayisi);

  return [
    selected.join(", "),
    selected_kat.join(" + "),
    katSayisiniBul2(selected_kat),
    kotAltiSayisi,
    kotUstuSayisi
  ];
};

window.onclick = function (event) {
  if (!event.target.matches(".label_button")) {
    const dropdowns = document.querySelectorAll(".dropdown-content");
    dropdowns.forEach((dropdown) => {
      if (dropdown.classList.contains("show")) {
        dropdown.classList.remove("show");
      }
    });
  }
  if (!event.target.matches(".dropbtnn")) {
    const dropdowns = document.querySelectorAll(".dropdown-contentt");
    dropdowns.forEach((dropdown) => {
      if (dropdown.classList.contains("show")) {
        dropdown.classList.remove("show");
      }
    });
  }
};

function toggleInput(checkbox) {
  var selectElement = document.getElementById(checkbox.id + "-select");
  if (checkbox.checked) {
    selectElement.style.display = "block";
  } else {
    selectElement.style.display = "none";
  }
};

// Tüm checkbox'lar için toggleInput fonksiyonunu ekle
var checkboxes = document.querySelectorAll(
  'input[type="checkbox"][name="bbbolumleri"]'
);
checkboxes.forEach(function (checkbox) {
  checkbox.addEventListener("change", function () {
    toggleInput(checkbox);
  });
  // Sayfa yüklenirken başlangıç durumunu kontrol et
  toggleInput(checkbox);
});

function addClass(menuId, itemCount) {
  var div = document.getElementById(`selectedValues-${menuId}-${itemCount}`);
  var newClass = document.getElementById(
    `katicerigiselect3-${menuId}-${itemCount}`
  );
  // Mevcut tüm sınıfları kaldır
  if (div.className) {
    div.className.split(" ").forEach(function (cls) {
      if (cls) {
        div.classList.remove(cls);
      }
    });
  }
  // Yeni sınıfı ekle
  div.classList.add(newClass.value);
};

function imarmanuel(type) {
  let element, manualElement, SpanElement;

  if (type === "kat") {
    element = document.getElementById("imaryukseklikkat");
    manualElement = document.getElementById("imaryukseklikkatmanuel");
  } else if (type === "metre") {
    element = document.getElementById("imaryukseklikmetre");
    manualElement = document.getElementById("imaryukseklikmetremanuel");
  } else if (type === "taks") {
    element = document.getElementById("taks");
    manualElement = document.getElementById("taksmanuel");
  } else if (type === "kaks") {
    element = document.getElementById("kaks");
    manualElement = document.getElementById("kaksmanuel");
  } else if (type === "yolaterk") {
    element = document.getElementById("yolaterk");
    manualElement = document.getElementById("yolaterkmanuel");
    textElement = document.getElementById("yolaterkmanueltext");
    eklentiElement1 = document.getElementById("imareklentietkilememekte");
    eklentiElement2 = document.getElementById("imareklentietkilemekte");
    eklentiElement3 = document.getElementById("imareklentiresmibelgevar");
    eklentiElement4 = document.getElementById("imareklentiresmibelgeyok");
  } else if (type === "bbkatkonumu") {
    element = document.getElementById("bbKatKonumCephe");
    //textElement = document.getElementById("bbkatkonumutext");
    manualElement = document.getElementById("bbKatKonumuManuel");
    manualTextElement = document.getElementById("bbkatkonumumanueltext");
  }

  if (element.value === "") {
    if (type == "yolaterk") {
      manualElement.style.display = "block";
      textElement.style.display = "block";
      eklentiElement1.style.display = "block";
      eklentiElement2.style.display = "block";
      eklentiElement3.style.display = "block";
      eklentiElement4.style.display = "block";
    } else if (type == "bbkatkonumu") {
      //textElement.style.display = "none";
      manualElement.style.display = "block";
      manualTextElement.style.display = "block";
    } else {
      manualElement.style.display = "block";
    }
  } else {
    if (type == "yolaterk") {
      manualElement.value = "";
      manualElement.style.display = "none";
      textElement.style.display = "none";
    } else if (type == "bbkatkonumu") {
      //textElement.style.display = "block";
      manualElement.style.display = "none";
      //manualTextElement.style.display = "none";
    } else {
      manualElement.value = "";
      manualElement.style.display = "none";
    }
  }
};

function imarbirleştir() {
  let ImarYukseklikKatElement = document.getElementById("imaryukseklikkat");
  let ImarYukseklikKatManuelElement = document.getElementById(
    "imaryukseklikkatmanuel"
  );
  let ImarYukseklikMetreElement = document.getElementById("imaryukseklikmetre");
  let ImarYukseklikMetreManuelElement = document.getElementById(
    "imaryukseklikmetremanuel"
  );
  let ImarTaksElement = document.getElementById("taks");
  let ImarTaksManuelElement = document.getElementById("taksmanuel");
  let ImarKaksElement = document.getElementById("kaks");
  let ImarKaksManuelElement = document.getElementById("kaksmanuel");
  let ImarCekmeonElement = document.getElementById("cekmeon");
  let ImarCekmeyanElement = document.getElementById("cekmeyan");
  let ImarCekmearkaElement = document.getElementById("cekmearka");
  let ImarYolaterkElement = document.getElementById("yolaterk");
  let ImarYolaterkmanuelElement = document.getElementById("yolaterkmanuel");

  var Itemimar1 =
    ImarYukseklikKatElement.value === "---"
      ? ""
      : `${ImarYukseklikKatElement.value}${ImarYukseklikKatManuelElement.value} kat`;
  var Itemimar2 =
    ImarYukseklikMetreElement.value === "---"
      ? ""
      : `hmaks:${ImarYukseklikMetreElement.value}${ImarYukseklikMetreManuelElement.value} m`;
  var Itemimar3 =
    ImarTaksElement.value === "---"
      ? ""
      : `TAKS:${ImarTaksElement.value}${ImarTaksManuelElement.value}`;
  var Itemimar4 =
    ImarKaksElement.value === "---"
      ? ""
      : `KAKS:${ImarKaksElement.value}${ImarKaksManuelElement.value}`;
  var Itemimar5 =
    ImarCekmeonElement.value === "---"
      ? ""
      : `ön çekme mesafesi ${ImarCekmeonElement.value} metre`;
  var Itemimar6 =
    ImarCekmeyanElement.value === "---"
      ? ""
      : `yan çekme mesafesi ${ImarCekmeyanElement.value} metre`;
  var Itemimar7 =
    ImarCekmearkaElement.value === "---"
      ? ""
      : `arka çekme mesafesi ${ImarCekmearkaElement.value} metre`;
  var Itemimar8 =
    ImarYolaterkElement.value === "yok"
      ? "net imar parseli olup terki ve kısıtlaması bulunmadığı"
      : `olup ~${ImarYolaterkmanuelElement.value} m² yola terkinin bulunduğu`;

  // if (ImarCekmearkaElement.value == "---"){
  //     var Itemimar7 = "";
  // } else {
  //     var Itemimar7 = `arka çekme mesafesi ${ImarCekmearkaElement.value} metre`;
  // }

  let Itemimar = [
    Itemimar1,
    Itemimar2,
    Itemimar3,
    Itemimar4,
    Itemimar5,
    Itemimar6,
    Itemimar7,
  ];
  let filteredItemimar = Itemimar.filter((item) => item !== "");

  return [filteredItemimar.join(", "), Itemimar8];
};

function projeRuhsatIskanbirlestir() {
  const ProjeSelect1Elements = document.querySelectorAll(
    `[id*="projeselect1-"]`
  );
  const ProjeSelect2Elements = document.querySelectorAll(
    `[id*="projeselect2-"]`
  );
  const DateProjeElements = document.querySelectorAll(`[id*="projeDate-"]`);
  const projeSelect1List = [];
  const projeSelect2List = [];
  const projeDateList = [];
  const Itemproje = [];

  const RuhsatIskanSelectElements = document.querySelectorAll(
    `[id*="projeRuhsatIskanselect-"]`
  );
  const RuhsatIskanDateElements = document.querySelectorAll(
    `[id*="projeRuhsatIskanDate-"]`
  );
  const RuhsatIskanTextElements = document.querySelectorAll(
    `[id*="projeRuhsatIskantext-"]`
  );
  const selectList = [];
  const dateList = [];
  const textList = [];
  const Itempri = [];
  const ItemProjeBelediye = [];
  const ItemRuhsat = [];
  const ItemIskan = [];

  // ProjeSelect1Elements.forEach((element, index) => {
  //   ele = element.options[element.selectedIndex].value;
  //   projeSelect1List.push(ele);

  //   const selectttElement = document.getElementById(
  //     "projeselect2-" + (index + 1)
  //   );    
  //   const webtapuyokOption = selectttElement.querySelector("#webtapuyok");
  //   webtapuyokOption.style.display = ele === "webtapu" ? "block" : "none";
  // });

  ProjeSelect1Elements.forEach((element, index) => {
    const ele = element.options[element.selectedIndex].value;
    projeSelect1List.push(ele);

    // selectttElement'i al
    const selectttElement = document.getElementById("projeselect2-" + (index + 1));
    if (!selectttElement) {
      console.warn(`projeselect2-${index + 1} öğesi bulunamadı.`);
      return; // Bu adımı atla
    }

    // webtapuyok öğesini al
    const webtapuyokOption = selectttElement.querySelector("#webtapuyok");
    if (!webtapuyokOption) {
      console.warn(`#webtapuyok öğesi projeselect2-${index + 1} içinde bulunamadı.`);
      return; // Bu adımı atla
    }

    // Görünürlüğü ayarla
    webtapuyokOption.style.display = ele === "webtapu" ? "block" : "none";
  });

  ProjeSelect2Elements.forEach((element) => {
    projeSelect2List.push(element.options[element.selectedIndex].value);
  });
  DateProjeElements.forEach((element) => {
    projeDateList.push(showDate3(element.value));
  });

  for (let i = 0; i < projeSelect1List.length; i++) {
    if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "mimariproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait bila tarihli mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "tadilatproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait bila tarihli tadilat projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli tadilat projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "katirtifaki"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait bila tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "katmulkiyeti"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait bila tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `Webtapu sisteminde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "projeyok"
    ) {
      Itemproje.push(
        `Webtapu sisteminde taşınmaza ait proje mevcut değildir.`
      );
    } else if (
      projeSelect1List[i] === "webtapu" &&
      projeSelect2List[i] === "webtapuyok"
    ) {
      Itemproje.push(`Tapu ve Kadastro Genel Müdürlüğünün projeleri taradığı dijital ortamda (Webtapu sisteminde), tapu projeleri 
                sistem arıza ve yoğunluğundan dolayı sistemden çekilememektedir. Bu sebeple taşınmaza ait proje ilgili belediyesinde 
                incelenmiş ve taşınmazın blok, kat ve konum olarak Belediye İmar Müdürlüğünde mevcut projesiyle uyumlu olduğu tespit 
                edilmiştir. Bu proje esas alınarak taşınmaza yasal ve mevcut durum değeri takdir edilmiştir.`);
    } else if (
      projeSelect1List[i] === "tapu" &&
      projeSelect2List[i] === "mimariproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait bila tarihli mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "tapu" &&
      projeSelect2List[i] === "tadilatproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait bila tarihli tadilat projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli tadilat projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "tapu" &&
      projeSelect2List[i] === "katirtifaki"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait bila tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "tapu" &&
      projeSelect2List[i] === "katmulkiyeti"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait bila tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        )
      } else {
        Itemproje.push(
          `İlgili Tapu Müdürlüğünde değerleme konusu taşınmaza ait ${projeDateList[i]} tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        )
      };
    } else if (
      projeSelect1List[i] === "tapu" &&
      projeSelect2List[i] === "projeyok"
    ) {
      Itemproje.push(
        `İlgili Tapu Müdürlüğünde taşınmaza ait proje mevcut değildir.`
      );
    } else if (
      projeSelect1List[i] === "belediye" &&
      projeSelect2List[i] === "mimariproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        let textt = `bila tarihli mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      } else {
        let textt = `${projeDateList[i]} tarihli mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      };
    } else if (
      projeSelect1List[i] === "belediye" &&
      projeSelect2List[i] === "tadilatproje"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        let textt = `bila tarihli tadilat projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      } else {
        let textt = `${projeDateList[i]} tarihli tadilat projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      };
    } else if (
      projeSelect1List[i] === "belediye" &&
      projeSelect2List[i] === "katirtifaki"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        let textt = `bila tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      } else {
        let textt = `${projeDateList[i]} tarihli kat irtifakına esas mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      };
    } else if (
      projeSelect1List[i] === "belediye" &&
      projeSelect2List[i] === "katmulkiyeti"
    ) {
      if (projeDateList[i] === "11.11.1111") {
        let textt = `bila tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      } else {
        let textt = `${projeDateList[i]} tarihli kat mülkiyetine esas mimari projesi incelenmiştir.`
        Itempri.push(textt)
        ItemProjeBelediye.push(textt)
      };
    } else if (
      projeSelect1List[i] === "belediye" &&
      projeSelect2List[i] === "projeyok"
    ) {
      let textt = `İlgili mimari projesi mevcut değildir.`
      Itempri.push(textt)
      ItemProjeBelediye.push(textt)
    }
  }

  //console.log("filteredItemproje:::", Itemproje.join("\n"));

  // *****************************************************************************************

  RuhsatIskanSelectElements.forEach((element) => {
    selectList.push(element.options[element.selectedIndex].value);
  });
  RuhsatIskanDateElements.forEach((element) => {
    dateList.push(showDate3(element.value));
  });
  RuhsatIskanTextElements.forEach((element) => {
    textList.push(element.value);
  });

  for (let i = 0; i < selectList.length; i++) {
    if (selectList[i] === "iskan") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli yapı kullanma izin belgesi incelenmiştir.`
        )
        ItemIskan.push(
          `${dateList[i]} tarihli yapı kullanma izin belgesi`
        )

      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yapı kullanma izin belgesi incelenmiştir.`
        )
        ItemIskan.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yapı kullanma izin belgesi`
        )
      };
    } else if (selectList[i] === "yeniyapiruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli yeni yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli yeni yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yeni yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yeni yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "tadilatruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli tadilat ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli tadilat ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı tadilat ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı tadilat ruhsatı`
        )
      };
    } else if (selectList[i] === "isimdegisikligiruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli isim değişikliği yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli isim değişikliği yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı isim değişikliği yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı isim değişikliği yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "yenilemeruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli yenileme yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli yenileme yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yenileme yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yenileme yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "yenidenruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli yeniden yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli yeniden yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yeniden yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı yeniden yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "katilavesiruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli kat ilavesi yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli kat ilavesi yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı kat ilavesi yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı kat ilavesi yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "ilaveruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli ilave yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli ilave yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı ilave yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı ilave yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "geciciruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli geçici yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli geçici yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı geçici yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı geçici yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "guclendirmeruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli güçlendirme yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli güçlendirme yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı güçlendirme yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı güçlendirme yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "dolguruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli dolgu yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli dolgu yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı dolgu yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı dolgu yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "istinatduvariruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli istinat duvarı yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli istinat duvarı yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı istinat duvarı yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı istinat duvarı yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "bahceduvariruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli bahçe duvarı yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli bahçe duvarı yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı bahçe duvarı yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı bahçe duvarı yapı ruhsatı`
        )
      };
    } else if (selectList[i] === "kullanimdegisikligiruhsati") {
      if (textList[i] === "") {
        Itempri.push(
          `${dateList[i]} tarihli kullanım değişikliği yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarihli kullanım değişikliği yapı ruhsatı`
        )
      } else {
        Itempri.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı kullanım değişikliği yapı ruhsatı incelenmiştir.`
        )
        ItemRuhsat.push(
          `${dateList[i]} tarih, ${textList[i]} sayılı kullanım değişikliği yapı ruhsatı`
        )
      };
    }
  }
  if (!selectList.includes("iskan")) {
    Itempri.push(
      `İlgili dosyasında taşınmaza ait yapı kullanma izin belgesi bulunmamaktadır.`
    );
    ItemIskan.push(
      `${showDate2(document.getElementById("belediyeDate").value)} tarihinde ${document.getElementById("ilce").value} Belediyesi İmar Arşivinde mevcut dosyasında yapılan incelemede yapı kullanma izin belgesine rastlanılmamıştır.`
    );
  }

  // console.log("selectList:::", selectList);
  // console.log("dateList:::", dateList);

  let yapimYili;
  for (let index = 0; index < selectList.length; index++) {
    const item = selectList[index];

    if (item.includes("ruhsat")) {
      // console.log("item:::", item);
      yapimYili = dateList[index];
      break; // İlk bulduğunda döngüyü keser
    } else {
      yapimYili = "";
      // yapimYili = "ruhsat bilgisi girilmemiş.";
    }
  }

  //console.log("filteredItempri:::", Itempri.join("\n"));
  //console.log("filteredItempri:::", Itempri.join("\n"));
  const sRuhsatBilgileri = ItemRuhsat.map((item) => `${item}`).join(", ");
  const sIskanBilgileri = ItemIskan.map((item) => `${item}`).join(", ");

  if (!selectList.includes("iskan")) {
    var resultIskanBilgileri = ItemIskan
  }
  else {
    var resultIskanBilgileri = `${showDate2(document.getElementById("belediyeDate").value)} tarihinde ${document.getElementById("ilce").value} Belediyesi İmar Arşivinde mevcut dosyasında yer alan ` + sIskanBilgileri + ` incelenmiştir.`;
  };

  // console.log("ItemProjeBelediye::", ItemProjeBelediye)
    // let ItemProjeBelediyeVakif = ItemProjeBelediye.map(item => item.replace(" incelenmiştir.", ""));
  let ItemProjeBelediyeVakif = ItemProjeBelediye.map((item, index) => 
    index === ItemProjeBelediye.length - 1 ? item : item.replace(/\s*incelenmiştir\.$/, ""));

  // console.log("Itemproje::", Itemproje)
  let ItemprojeVakif = Itemproje.length === 1 
    ? `<p>${Itemproje[0]}</p>` 
    : Itemproje.map(item => `<p>${item}</p>`).join("");  

  return [
    Itemproje.map((item) => `<p>- ${item}</p>`).join(""),
    Itempri.map((item) => `<p>- ${item}</p>`).join(""),
    getYearFromDate(yapimYili),
    // `${(document.getElementById("tarih").value)} tarihinde; ` + ItemprojeVakif,
    ItemprojeVakif,
    `${showDate2(document.getElementById("belediyeDate").value)} tarihinde ${document.getElementById("ilce").value} Belediyesinde değerleme konusu taşınmazın imar arşiv dosyasında taşınmaza ait ` + ItemProjeBelediyeVakif,
    `${showDate2(document.getElementById("belediyeDate").value)} tarihinde ${document.getElementById("ilce").value} Belediyesi İmar Arşivinde mevcut dosyasında yer alan ` + sRuhsatBilgileri + ` incelenmiştir.`,
    resultIskanBilgileri
  ];
};

function aykirilik() {
  const select_aykirilik = document.getElementById("bbaykiriliklarselect");
  const bbaykiriliklartextElement =
    document.getElementById("bbaykiriliklartext");

  // if (select_aykirilik.value === "yok"){
  //     var ItemAykirilik = "Değerleme konusu bağımsız bölüm içinde yapılan incelemede taşınmazın projesine uygun olduğu gözlenmiştir.";
  // } else {
  //     var ItemAykirilik = bbaykiriliklartextElement.value;
  // }
  var Item =
    select_aykirilik.value === "var"
      ? bbaykiriliklartextElement.value
      : "Değerleme konusu bağımsız bölüm içinde yapılan incelemede taşınmazın projesi ile alan ve mimari olarak uyumlu olduğu gözlenmiştir.";

  return Item;
};

// function olumsuzBelge() {
//   const select_olumsuzbelge = document.getElementById("bbolumsuzbelgeselect");
//   const bbolumsuzbelgetextElement =
//     document.getElementById("bbolumsuzbelgetext");

//   var Item =
//     select_olumsuzbelge.value === "var"
//       ? `- ${bbolumsuzbelgetextElement.value}`
//       : "- Taşınmazın dosyasında herhangi bir encümen kararı, yapı tatil zaptı, yıkım kararı vb. olumsuz belge bulunmadığı şifahen öğrenilmiştir.";

//   return Item;
// };

function olumsuzBelge() {
  const select_olumsuzbelge = document.getElementById("bbolumsuzbelgeselect");
  const bbolumsuzbelgetextElement = document.getElementById("bbolumsuzbelgetext");
  const belediyeDate = document.getElementById("belediyeDate").value;
  const belediyeMahalle = document.getElementById("ilce").value;

  let item, item2;

  if (select_olumsuzbelge.value === "var") {
    item = `- ${bbolumsuzbelgetextElement.value}`;
    item2 = `${bbolumsuzbelgetextElement.value}`;
  } else {
    item = "- Taşınmazın dosyasında herhangi bir encümen kararı, yapı tatil zaptı, yıkım kararı vb. olumsuz belge bulunmadığı şifahen öğrenilmiştir.";
    item2 = `${showDate2(belediyeDate)} tarihinde, konu taşınmazın ${belediyeMahalle} Belediyesi İmar Arşiv Müdürlüğünde bulunan dosyasında herhangi bir cezai tutanak, zabıt, yıkım kararı vb. evraka rastlanmamıştır.`;
  }

  return [item, item2];
};

function takbisFarklilikVar() {
  const textarea = document.getElementById("takbisFarklilikVarText");
  const takbisTarih = document.getElementById("tarih");
  const takbisFarklilikSelectTapu = document.getElementById("takbisFarklilikSelectTapu");
  //const takbisFarklilikSec = document.getElementById("takbisFarklilikSecLabel"); 
  const varYokElement = document.getElementById("takbisFarklilikSelectVarYok");
  // console.log("FarklilikSecText:", updateSelectedFarklilik(['takbisFarklilikSec']))

  const contextfarklilikYok = `${takbisTarih.value} tarihinde alınmış olan Tapu Müdürlüğü kaydı (Takbis) ile tarafımıza iletilen ${takbisFarklilikSelectTapu.value} arasında farklılığa rastlanılmamıştır.`;
  const contextfarklilikVar = `${takbisTarih.value} tarihinde alınmış olan Tapu Müdürlüğü kaydı (Takbis) ile tarafımıza iletilen ${takbisFarklilikSelectTapu.value} karşılaştırıldığında ${takbisFarklilikSelectTapu.value}ndeki ${updateSelectedFarklilik(['takbisFarklilikSec'])} bilgilerinin farklı olduğu tespit edilmiş olup, güncel takbis kaydı esas alınarak rapor düzenlenmiştir.`;

  textarea.value =
    varYokElement.value === "var" ? contextfarklilikVar : contextfarklilikYok;
};

function yapidenetimIskanYok() {
  const textarea = document.getElementById("tabiiIskanYokText");
  const firmaAdi = document.getElementById("yapiDenetimFirmaText");
  const yapidenetimInsSev = document.getElementById("yapiDenetimInsSevText");
  const mahalInsSev = document.getElementById("mahalInsSevText");
  const fesihElement = document.getElementById("fesihselect");
  const fesihTarihiElement = document.getElementById("fesihdate");

  const contextFesihYok = `Taşınmazın bulunduğu binaya ait yapı kullanma izin belgesi bulunmamakta olup yapı ruhsatının geçerlilik süresi bulunmaktadır. Alınan sözlü bilgilere göre taşınmazın bulunduğu binanın Yapı Denetim Şirketinin ${firmaAdi.value} Yapı Denetim Ltd. Şti. olduğu, sözleşme feshi söz konusu olmadığı, şirketin faal olduğu, yapının gerçekleşme oranının %${yapidenetimInsSev.value} olduğu ilgili belediye yetkililerin tarafından beyan edilmiştir. Mahallinde taşınmazın inşaat seviyesi %${mahalInsSev.value} dür. Sonuç olarak; yasal işlemler devam ettiği ve herhangi bir olumsuz evrak olmadığı için mahallindeki inşaat seviyesi dikkate alınarak değerleme yapılmıştır.`;
  const contextFesihVar = `Taşınmazın bulunduğu binaya ait yapı kullanma izin belgesi bulunmamakta olup yapı ruhsatının geçerlilik süresi bulunmaktadır. Alınan sözlü bilgilere göre taşınmazın bulunduğu binanın Yapı Denetim Şirketinin en son ${firmaAdi.value
    } Yapı Denetim Ltd. Şti. olduğu, ${showDate3(
      fesihTarihiElement.value
    )} tarihinde sözleşme feshi olduğu, fesih tarihinde yapının gerçekleşme oranının %${yapidenetimInsSev.value
    } olduğu, fesih tarihinden sonra yeni Yapı Denetim Şirketi anlaşmasının olmadığı ilgili belediye yetkililerin tarafında beyan edilmiştir. Mahallinde taşınmazın inşaat seviyesi %${mahalInsSev.value
    } dür. Sonuç olarak; yasal işlemler devam ettiği ve herhangi bir olumsuz evrak olmadığı için mahallindeki inşaat seviyesi dikkate alınarak değerleme yapılmıştır.`;

  textarea.value =
    fesihElement.value === "var" ? contextFesihVar : contextFesihYok;
};

function yapidenetim() {
  const select_yapidenetim = document.getElementById("yapidenetimselect");
  const tabiiIskanYokTextElement = document.getElementById("tabiiIskanYokText");

  if (select_yapidenetim.value === "tabidegil") {
    var Item =
      "Taşınmazın konumlandığı bina, 13.07.2001 tarih ve 24461 sayılı Yapı Denetim kanunundan önce inşa edilmiş olması nedeniyle yapı denetim kanununa tabi değildir.";
  }
  if (select_yapidenetim.value === "yapidenetimIskanvar") {
    var Item =
      "Taşınmaza ait yapı kullanım belgesi alınmış olması sebebiyle iş bitirme belgesi mevcuttur.";
  }
  if (select_yapidenetim.value === "yapidenetimIskanyok") {
    var Item = tabiiIskanYokTextElement.value;
  }

  return Item;
};

function otopark() {
  const select_otopark = document.getElementById("otoparkselect");

  if (select_otopark.value === "Otopark imkanı bulunmayan") {
    var Item = "Yok";
  }

  if (select_otopark.value === "Kapalı otopark imkanı bulunan") {
    var Item = "Kapalı otopark imkanı mevcuttur.";
  }

  if (
    select_otopark.value ===
    "Parsel alanı içerisinde açık otopark imkanı bulunan"
  ) {
    var Item = "Parsel alanı içerisinde açık otopark imkanı mevcuttur.";
  }

  if (select_otopark.value === "Açık ve kapalı otopark imkanı bulunan") {
    var Item = "Açık ve kapalı otopark imkanı mevcuttur.";
  }

  //console.log("Item:", Item)

  return Item;
};

function deleteItemKaticerigiMenu(id) {
  const itemMenuText = document.getElementById(`MenuText-${id}`);
  const item = document.getElementById(`katicerigiItem-${id}`);
  const AllMenuTextElement = document.getElementById(`AllMenuText`);
  item.remove();
  itemMenuText.remove();
  AllMenuTextElement.textContent = "";
};

function bbkonumbirlestir() {
  const select_bb = document.getElementById("bbKonutTespiti");
  const bbyapilamiyortextElement = document.getElementById(
    "bbkonumTespitiYapilamiyortext"
  );
  //console.log("select_bb:", select_bb.value)
  //console.log("bbyapilamiyortextElement:", bbyapilamiyortextElement.value)

  if (select_bb.value === "yapilamiyor") {
    var Itembb = bbyapilamiyortextElement.value;
  } else {
    var Itembb = `Değerlemeye konu taşınmazın bağımsız bölüm bazında projesinde planlanan katta ve konumda olduğu ${select_bb.value} incelenen projesinden tespit edilmiştir.`;
  }

  return Itembb;
};

function bbBlokKonumBirlestir() {
  const bbBlokElement = document.getElementById("bbBlok");
  const bbBlokKonumYonElement = document.getElementById("bbBlokKonumYon");
  const bbBlokKonumTarifElement = document.getElementById("bbBlokKonumTarif");
  const bbBlokKonumTextareaElement = document.getElementById("bbBlokKonumTextarea");

  SelectbbBlokKonumYon = bbBlokKonumYonElement.options[bbBlokKonumYonElement.selectedIndex].value;
  SelectbbBlokKonumTarif = bbBlokKonumTarifElement.options[bbBlokKonumTarifElement.selectedIndex].value;

  // bbBlokKonumTextareaElement.style.removeProperty("height"); // height stilini kaldırır

  bbBlokKonumTextareaElement.value = `${bbBlokElement.value} blok, parselin ${SelectbbBlokKonumYon} ${SelectbbBlokKonumTarif} yer almaktadır.`;

  //return bbBlokKonumTextareaElement.textContent
};

function bbKatKonumBirlestir() {
  const bbKatKonumTarifElement = document.getElementById("bbKatKonumTarif");
  const bbKatKonumCepheElement = document.getElementById("bbKatKonumCephe");
  const bbKatKonumuManuelElement = document.getElementById("bbKatKonumuManuel");

  const bbNoElement = document.getElementById("bbno_");
  const atGirisSeviyesiElement = document.getElementById("anatasinmazgirisseviyesi");

  const yonSayisiElement = sayiyiYaziyaCevir(updateSelecteddd(["bbcepheyonleri"])[1])
  const cepheYonleriElement = updateSelecteddd(["bbcepheyonleri"])[0]

  const bbKatNoElement2 = document.getElementById("katno");
  const isNotNumeric = !/^\d+$/.test(bbKatNoElement2.value);
  const suffix = isNotNumeric ? "" : ". normal";
  const bbKatNoElement = bbKatNoElement2.value.toLowerCase() + suffix;

  SelectbbKatKonumTarif = bbKatKonumTarifElement.options[bbKatKonumTarifElement.selectedIndex].value;

  if (bbKatKonumCepheElement.value === "") {
    SelectbbKatKonumCephe = bbKatKonumuManuelElement.value;
  } else {
    SelectbbKatKonumCephe = bbKatKonumCepheElement.options[bbKatKonumCepheElement.selectedIndex].value;
  }

  if (bbKatKonumTarifElement.value === "blok giriş kapısı yönünden") {
    var sss = "bloğun";
  } else {
    var sss = "binanın";
  }

  if (bbKatKonumTarifElement.value === "yol cephesinden") {
    var item = `Değerleme konusu ${bbNoElement.value} bağımsız bölüm numaralı taşınmaz, ${SelectbbKatKonumTarif} bakıldığında ${sss} ${bbKatNoElement}  katında, ${SelectbbKatKonumCephe} kalmakta olup ${yonSayisiElement} yöne(${cepheYonleriElement}) cephelidir.`;
  } else {
    var item = `Değerleme konusu ${bbNoElement.value} bağımsız bölüm numaralı taşınmaz, ${atGirisSeviyesiElement.value}tan olan ${SelectbbKatKonumTarif} bakıldığında ${sss} ${bbKatNoElement}  katında, ${SelectbbKatKonumCephe} kalmakta olup ${yonSayisiElement} yöne(${cepheYonleriElement}) cephelidir.`;
  }
  return item;
};

function binakonumbirlestir() {
  let blokKonumTespitiElement = document.getElementById("blokKonutTespiti");
  let vplaniElement = document.getElementById("selectedValue-blokKonumItems1");
  let nkrokiElement = document.getElementById("selectedValue-blokKonumItems2");
  let kplaniElement = document.getElementById("selectedValue-blokKonumItems3");
  let yapilamiyorElement = document.getElementById(
    "konumTespitiYapilamiyortext"
  );
  //console.log("yapilamiyorElement:", yapilamiyorElement.value)

  if (blokKonumTespitiElement.value === "yapilamiyor") {
    var ItemblokKonumTespiti = yapilamiyorElement.value;
    //console.log("ItemblokKonumTespiti:", ItemblokKonumTespiti)
  }

  if (blokKonumTespitiElement.value === "yapiliyor") {
    var Itemvplani =
      vplaniElement.textContent === ""
        ? ""
        : `${vplaniElement.textContent} gösterilmiş vaziyet planı`;
    var Itemnkroki =
      nkrokiElement.textContent === ""
        ? ""
        : `${nkrokiElement.textContent} gösterilmiş numarataj krokisi`;
    var Itemkplani =
      kplaniElement.textContent === ""
        ? ""
        : `${kplaniElement.textContent} gösterilmiş kat planları`;

    let ItemyapiliyorList = [Itemvplani, Itemnkroki, Itemkplani];
    let filteredItemyapiliyorList = ItemyapiliyorList.filter(
      (item) => item !== ""
    );

    var ItemblokKonumTespiti = `Değerlemeye konu taşınmazın bina/blok bazında konum tespiti; mimari projesindeki ${filteredItemyapiliyorList.join(
      ", "
    )} üzerinden yapılmaktadır.`;
  }
  //console.log("Itemyapiliyor:", Itemyapiliyor)
  return ItemblokKonumTespiti;
};

function htmlEkle(icon, OzelDurumDiv, OzelDurumtext, varOzelDurum) {
  const containers = document.querySelectorAll(`.${OzelDurumDiv}`);
  const ruhsatOzelDurumtextElement = document.getElementById(OzelDurumtext);

  containers.forEach((container) => {
    // container içeriğini temizle
    container.innerHTML = `<p class="targetParagrah"></p>`;

    // targetParagrah'ten sonra yeni içerik ekle
    const newParagraph = container.querySelector(".targetParagrah");
    const textValue = ruhsatOzelDurumtextElement.value.trim(); // Boşlukları temizle
    const displayIcon = textValue ? icon : ""; // İçerik boşsa icon boş olsun

    newParagraph.insertAdjacentHTML(
      "afterend",
      `<p>${displayIcon} <span id="${varOzelDurum}">${textValue}</span></p>`
    );
  });
};

function sayiyiYaziyaCevir(sayi) {
  const birler = [
    "sıfır",
    "bir",
    "iki",
    "üç",
    "dört",
    "beş",
    "altı",
    "yedi",
    "sekiz",
    "dokuz",
  ];
  const onlar = [
    "on",
    "yirmi",
    "otuz",
    "kırk",
    "elli",
    "altmış",
    "yetmiş",
    "seksen",
    "doksan",
  ];

  if (sayi < 10) {
    return birler[sayi];
  } else if (sayi < 100) {
    let on = Math.floor(sayi / 10);
    let bir = sayi % 10;
    return onlar[on - 1] + (bir !== 0 ? " " + birler[bir] : "");
  }

  // Daha büyük sayılar için genişletilebilir
  return sayi.toString();
};

function katSayisiniBul(dizi) {
  const katSayisi = {
    bodrumKat: 0,
    zeminKat: 0,
    normalKat: 0,
    terasKat: 0,
    asmaKat: 0,
    catiKat: 0,
  };

  dizi.forEach((item) => {
    if (item.includes("bodrum katta")) {
      katSayisi.bodrumKat++;
    } else if (item.includes("zemin katta")) {
      katSayisi.zeminKat++;
    } else if (item.includes("normal katta")) {
      katSayisi.normalKat++;
    } else if (item.includes("teras katta")) {
      katSayisi.terasKat++;
    } else if (item.includes("asma katta")) {
      katSayisi.asmaKat++;
    } else if (item.includes("çatı katında")) {
      katSayisi.catiKat++;
    }
  });

  return katSayisi;
};

function katSayisiniBul2(liste) {
  const toplam = liste.reduce((toplam, eleman) => {
    const sayi = parseInt(eleman);
    return isNaN(sayi) ? toplam : toplam + sayi;
  }, 0);
  return toplam;
};

function showDate1(dateInput) {
  const selectedDate = dateInput;

  if (selectedDate) {
    const dateParts = selectedDate.split("-");
    var formattedDate = `${dateParts[2]}.${dateParts[1]}.${dateParts[0]}`;
  } else {
    alert("Lütfen Temel Bilgiler sekmesindeki değerleme tarihini seçiniz!");
  }
  return formattedDate;
};

function showDate2(dateInput) {
  const selectedDate = dateInput;

  if (selectedDate) {
    const dateParts = selectedDate.split("-");
    var formattedDate = `${dateParts[2]}.${dateParts[1]}.${dateParts[0]}`;
  } else {
    alert(
      "Lütfen Belediye Dosya İncelemesi sekmesindeki belediye inceleme tarihini seçiniz!"
    );
  }
  return formattedDate;
};

function showDate3(dateInput) {
  const selectedDate = dateInput;
  const dateParts = selectedDate.split("-");
  var formattedDate = `${dateParts[2]}.${dateParts[1]}.${dateParts[0]}`;

  return formattedDate;
};

function getYearFromDate(dateString) {
  // Tarihi gün, ay ve yıl olarak ayır
  let parts = (dateString || "").split(".");
  // const parts = dateString.split('.');
  // Yıl bilgisi en son elemandır
  const year = parts[2];
  return year;
};

function setTodayDate() {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();

  const formattedDate = `${year}-${month}-${day}`; // "YYYY-MM-DD" formatı
  document.getElementById("date").value = formattedDate; // Input değerini ata
};

function belediyeTarihiDuzenle() {
  document.getElementById("belediyeDate").value =
    document.getElementById("date").value;
};

async function readPDF() {
  const fileInput = document.getElementById("pdfInput");
  const file = fileInput.files[0];

  if (file) {
    const fileReader = new FileReader();

    // `Promise` ile `FileReader`'ın `onload` olayını yakalıyoruz
    return new Promise((resolve, reject) => {
      fileReader.onload = async function () {
        try {
          const typedArray = new Uint8Array(this.result);
          const pdf = await pdfjsLib.getDocument(typedArray).promise;
          //const pdf = await pdfjsLib.getDocument({data: typedArray}).promise;
          let textContent = "";
          const numPages = pdf.numPages;

          for (let i = 1; i <= numPages; i++) {
            const page = await pdf.getPage(i);
            const text = await page.getTextContent();
            const pageText = text.items.map((item) => item.str).join(" ");
            //textContent += `Sayfa ${i}: ${pageText}\n\n`;
            textContent += `${pageText} `;
          }
          //console.log("textContent:::\n", textContent);

          resolve(textContent); // `textContent`'ı döndür
        } catch (error) {
          reject(error); // Hata durumunda `Promise`'ı reddet
        }
      };
      fileReader.onerror = function (error) {
        reject(error); // `FileReader` hatası durumunda `Promise`'ı reddet
      };
      fileReader.readAsArrayBuffer(file);
    });
  } else {
    // `Promise`'ı reddederek hata mesajı döndür
    return Promise.reject("Lütfen bir PDF dosyası seçin.");
  }
};

async function extractData() {
  const metin = await readPDF();
  return new Promise((resolve) => {
    const extractedData = {
      tarih: "",
      saat: "",
      kaydiOlusturan: "",
      makbuzNo: "",
      dekontNo: "",
      basvuruNo: "",
      tasinmazKimlikNo: "",
      eslesme_il: "",
      eslesme_ilce: "",
      mahalleReg: "",
      mevkii: "",
      cilt: "",
      sayfa: "",
      adaReg: "",
      parselReg: "",
      yuzolcumuReg: "",
      bbnitelikReg: "",
      bbbrutYuzolcumuReg: "",
      bbnetYuzolcumuReg: "",
      blokReg: "",
      katReg: "",
      girisReg: "",
      bbnoReg: "",
      arsapaypaydaReg: "",
      arsapayReg: "",
      arsapaydaReg: "",
      atnitelikReg: "",
      malikReg: "",
    };

    // Tarih bilgisini ayıklama
    const tarihsaatRegex = /(\d{1,2})-(\d{1,2})-(\d{4})-(\d{2}:\d{2})/;
    const eslesmetarihsaat = metin.match(tarihsaatRegex);
    if (eslesmetarihsaat) {
      const gun = eslesmetarihsaat[1].padStart(2, "0"); // Gün
      const ay = eslesmetarihsaat[2].padStart(2, "0"); // Ay
      const yil = eslesmetarihsaat[3]; // Yıl
      extractedData.saat = eslesmetarihsaat[4].trim(); // Saat

      extractedData.tarih = `${gun}.${ay}.${yil}`.trim();
    }

    // Kaydı oluşturan kişi bilgisi ayıklama
    const kaydiOlusturanRegex = /Kaydı\s*Oluşturan:\s*(.*?)\s*Makbuz\s*No/;
    extractedData.kaydiOlusturan = metin.match(kaydiOlusturanRegex)?.[1].trim();

    //Makbuz No Dekont No Başvuru No bilgisi ayıklama
    const veriAyiklaRegex =
      /Makbuz\s*No\s*Dekont\s*No\s*Başvuru\s*No\s*(.*?)\s*TAPU\s*KAYIT\s*BİLGİSİ/;
    const ayiklananVeri = metin.match(veriAyiklaRegex)?.[1].trim();
    const veriler = ayiklananVeri.split(/\s+/);
    extractedData.makbuzNo = veriler[0].trim();
    extractedData.dekontNo = veriler[1].trim();
    extractedData.basvuruNo = veriler[2].trim();

    // Taşınmaz kimlik no bilgileri ayıklama
    const tasinmazKimlikRegex = /Taşınmaz  Kimlik  No:\s*(\d+)/;
    extractedData.tasinmazKimlikNo = metin
      .match(tasinmazKimlikRegex)?.[1]
      .trim();

    // İl ve İlçe bilgileri ayıklama
    const ilIlceRegex = /İl\/ İlçe:\s*(.*?)\s*Kurum\s*Adı/;
    const eslesmeililce = metin.match(ilIlceRegex)[1].split("/");
    const eslesme_ilElement = eslesmeililce[0].trim();
    const eslesme_ilceElement = eslesmeililce[1].trim();
    extractedData.eslesme_il =
      eslesme_ilElement.charAt(0).toUpperCase() +
      eslesme_ilElement.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR");
    extractedData.eslesme_ilce =
      eslesme_ilceElement.charAt(0).toUpperCase() +
      eslesme_ilceElement.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR");

    // Mahalle bilgisi ayıklama
    const mahalleRegex = /Mahalle\/ Köy\s*Adı:\s*(.*?)\s*(Mah\s*)?Mevkii/;
    const mahalleElement = metin
      .match(mahalleRegex)?.[1]
      .trim()
      .split(" Mah")[0];
    const mahalleElementSplit = mahalleElement
      .split(" ")
      .filter((item) => item !== "");
    if (mahalleElementSplit.length > 1) {
      extractedData.mahalleReg = mahalleElementSplit
        .map(
          (kelime) =>
            kelime.charAt(0).toUpperCase() +
            kelime.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR")
        )
        .join(" ");
    } else {
      extractedData.mahalleReg =
        mahalleElement.charAt(0).toUpperCase() +
        mahalleElement.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR");
    }

    // Mevkii bilgisi ayıklama
    const mevkiiRegex = /Mevkii:\s*(.*?)\s*Cilt/;
    const mevkiiElement = metin.match(mevkiiRegex)[1].trim();
    const mevkiiElementSplit = mevkiiElement
      .split(" ")
      .filter((item) => item !== "");
    if (mevkiiElementSplit.length > 1) {
      extractedData.mevkii = mevkiiElementSplit
        .map(
          (kelime) =>
            kelime.charAt(0).toUpperCase() +
            kelime.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR")
        )
        .join(" ");
    } else {
      extractedData.mevkii =
        mevkiiElementSplit[0].charAt(0).toUpperCase() +
        mevkiiElementSplit[0].slice(1).replace(/I/g, "ı").toLowerCase("tr-TR");
    }

    // Cilt Sayfa No bilgisi ayıklama
    const ciltsayfaRegex = /Cilt\/ Sayfa  No:\s*(\d+\/\d+)/;
    const ciltsayfaElement = metin.match(ciltsayfaRegex)[1].trim().split("/");
    extractedData.cilt = ciltsayfaElement[0].trim();
    extractedData.sayfa = ciltsayfaElement[1].trim();
    //console.log("mevkiiElement:", ciltsayfaElement);

    // Ada Parsel bilgisi ayıklama
    const adaParselRegex = /Ada\/ Parsel:\s*([\d\/]+)/;
    const adaParselElement = metin.match(adaParselRegex)?.[1].split("/");
    extractedData.adaReg = adaParselElement[0].trim();
    extractedData.parselReg = adaParselElement[1].trim();

    // Yüzölçümü bilgisi ayıklama
    const yuzolcumuRegex = /Yüzölçüm\(m2\):\s*([\d.]+)/;
    extractedData.yuzolcumuReg = metin
      .match(yuzolcumuRegex)[1]
      .trim()
      .replace(".", ",");

    // BB Nitelik bilgisi ayıklama
    // Ayıklama fonksiyonu
    const extractBetween = (text, startKey, endKey) => {
      const regex = new RegExp(`${startKey}\\s*(.*?)\\s*${endKey}`);
      const match = text.match(regex);
      return match ? match[1].trim() : null;
    };
    const bbnitelikRegElement = extractBetween(
      metin,
      "Bağımsız  Bölüm  Nitelik:",
      "Bağımsız  Bölüm  Brüt  YüzÖlçümü:"
    );
    const bbnitelikRegElementSplit = bbnitelikRegElement
      .split(" ")
      .filter((item) => item !== "");
    // İlk harfi büyük yapma ve 'I' harflerini 'ı' ile değiştirme işlevi
    const formatText = (bbnitelikRegElementSplit) =>
      bbnitelikRegElementSplit.charAt(0).toUpperCase() +
      bbnitelikRegElementSplit.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR");
    // Nitelik bilgisi işlemi
    extractedData.bbnitelikReg =
      bbnitelikRegElementSplit.length > 0
        ? bbnitelikRegElementSplit.length > 1
          ? bbnitelikRegElementSplit.map(formatText).join(" ")
          : formatText(bbnitelikRegElementSplit[0])
        : "";
    extractedData.bbbrutYuzolcumuReg = extractBetween(
      metin,
      "Bağımsız  Bölüm  Brüt  YüzÖlçümü:",
      "Bağımsız  Bölüm  Net  YüzÖlçümü:"
    ).replace(".", ",");
    extractedData.bbnetYuzolcumuReg = extractBetween(
      metin,
      "Bağımsız  Bölüm  Net  YüzÖlçümü:",
      "Blok/"
    ).replace(".", ",");

    // Blok/ Kat/ Giriş/ BBNo: bilgisi ayıklama
    extractedData.blokReg = extractBetween(
      metin,
      "Blok/ Kat/ Giriş/ BBNo:",
      "Arsa  Pay/"
    ).split("/")[0];
    const katRegElement =
      extractBetween(metin, "Blok/ Kat/ Giriş/ BBNo:", "Arsa  Pay/").split(
        "/"
      )[1] || "";
    const katRegElementSplit = katRegElement
      .split(" ")
      .filter((item) => item !== "");
    if (bbnitelikRegElementSplit.length > 0) {
      if (katRegElementSplit.length > 1) {
        extractedData.katReg = katRegElementSplit
          .map(
            (kelime) =>
              kelime.charAt(0).toUpperCase() +
              kelime.slice(1).replace(/I/g, "ı").toLowerCase("tr-TR")
          )
          .join(" ");
      } else {
        extractedData.katReg =
          katRegElementSplit[0].charAt(0).toUpperCase() +
          katRegElementSplit[0]
            .slice(1)
            .replace(/I/g, "ı")
            .toLowerCase("tr-TR");
      }
    } else {
      extractedData.katReg = "";
    }
    extractedData.girisReg =
      extractBetween(metin, "Blok/ Kat/ Giriş/ BBNo:", "Arsa  Pay/").split(
        "/"
      )[2] || "";
    extractedData.bbnoReg =
      extractBetween(metin, "Blok/ Kat/ Giriş/ BBNo:", "Arsa  Pay/").split(
        "/"
      )[3] || "";

    // Arsa  Pay/ Payda bilgisi ayıklama
    extractedData.arsapaypaydaReg = extractBetween(
      metin,
      "Arsa  Pay/ Payda:",
      "Ana  Taşınmaz  Nitelik:"
    ).trim();
    extractedData.arsapayReg =
      extractBetween(
        metin,
        "Arsa  Pay/ Payda:",
        "Ana  Taşınmaz  Nitelik:"
      ).split("/")[0] || "";
    extractedData.arsapaydaReg =
      extractBetween(
        metin,
        "Arsa  Pay/ Payda:",
        "Ana  Taşınmaz  Nitelik:"
      ).split("/")[1] || "";

    // Ana  Taşınmaz  Nitelik bilgisi ayıklama
    const atnitelikReg1 = extractBetween(
      metin,
      "Ana  Taşınmaz  Nitelik:",
      "TAŞINMAZA  AİT"
    );
    const atnitelikReg2 = extractBetween(
      metin,
      "Ana  Taşınmaz  Nitelik:",
      "MÜLKİYET  BİLGİLERİ"
    );
    extractedData.atnitelikReg = (atnitelikReg1 || atnitelikReg2).trim();

    // Malik bilgisi ayıklama
    const startKey = "Toplam  Metrekare";
    const endKey1 = "MÜLKİYETE  AİT  REHİN  BİLGİLERİ";
    const endKey2 = "Bu  belgeyi  akıllı";
    const malikReg1 = extractBetween(metin, startKey, endKey1);
    const malikReg2 = extractBetween(metin, startKey, endKey2);
    extractedData.malikReg = (malikReg1 || malikReg2)
      .split(") ")[1]
      .split(":")[0]
      .split(" V ")[0]
      .trim();

    //return extractedData;
    resolve(extractedData);
  });
};

async function handleExtractPDFData() {
  try {
    var data = await extractData();
    const valueElementIds = {
      tarih: "tarih",
      saat: "saat",
      tasinmazno: "tasinmazKimlikNo",
      il: "eslesme_il",
      ilce: "eslesme_ilce",
      mahalle: "mahalleReg",
      mevkii: "mevkii",
      cilt: "cilt",
      sayfa: "sayfa",
      ada: "adaReg",
      parsel: "parselReg",
      parselyuzolcumu: "yuzolcumuReg",
      bbnitelik: "bbnitelikReg",
      blok: "blokReg",
      giris: "girisReg",
      bbno_: "bbnoReg",
      katno_: "katReg",
      arsapay: "arsapayReg",
      arsapayda: "arsapaydaReg",
      atnitelik: "atnitelikReg",
      malik: "malikReg",
      katno: "katReg",
      daireno: "bbnoReg",
      belediyeMahalle: "mahalleReg",
      // varbelediyeTarihi: "mahalleReg",
      bbBlok: "blokReg"
    };
    // Object.keys(valueElementIds).forEach((id) => {
    //   document.getElementById(id).value = data[valueElementIds[id]];
    // });

    Object.keys(valueElementIds).forEach((id) => {
      const element = document.getElementById(id);
      if (!element) {
        console.warn(`valueElementIds with ID "${id}" does not exist in the DOM.`);
      } else {
        // element.value = data[valueElementIds[id]];
        element.value = data[valueElementIds[id]] || "";

      }
    });

    // Object.keys(valueElementClasses).forEach((className) => {
    //   const elements = document.querySelectorAll(`.${className}`);
    //   if (elements.length === 0) {
    //     console.warn(`valueElementClasses with class "${className}" does not exist in the DOM.`);
    //   } else {
    //     elements.forEach((element) => {
    //       // element.value = data[valueElementClasses[className]];
    //       element.value = data[valueElementClasses[className]] || "";
    //     });
    //   }
    // });

    // const textContentClassNames = {
    //   varil_: "eslesme_il",
    //   varilce_: "eslesme_ilce",
    //   varilce2: "eslesme_ilce",
    //   varilce3: "eslesme_ilce",
    //   //varMahalle: "mahalleReg",
    //   // varbbno: "bbnoReg",
    //   //varbbno2: "bbnoReg",
    //   // varKatNo: "katReg",
    //   // varKatNo2: "katReg"
    // };

    // Object.keys(textContentelementIds).forEach((id) => {
    //   document.getElementById(id).textContent = data[textContentelementIds[id]];
    // });

    // Object.keys(textContentelementIds).forEach((id) => {
    //   const element = document.getElementById(id);
    //   if (!element) {
    //     console.warn(`textContentelementIds with ID "${id}" does not exist in the DOM.`);
    //   } else {
    //     element.value = data[textContentelementIds[id]];
    //   }
    // });

    // Object.keys(textContentClassNames).forEach((className) => {
    //   const elements = document.querySelectorAll(`.${className}`);
    //   if (elements.length === 0) {
    //     console.warn(`textContentClassNames with class "${className}" does not exist in the DOM.`);
    //   } else {
    //     elements.forEach((element) => {
    //       element.value = data[textContentClassNames[className]];
    //     });
    //   }
    // });


  } catch (error) {
    console.error("Bir hata oluştu:", error);
  }
  return data;
};

function adjustHeight(element) {
  element.style.height = "40px"; // Yüksekliği ayarla
  //console.log("element.scrollHeight:", element.scrollHeight)
  element.style.height = element.scrollHeight + "px"; // Yeni yüksekliği ayarla
};

function adjustHeightAutomatic(element) {
  const select_satisKanaati = document.getElementById("satisKanaatiSelect");

  var textarea;

  if (element === "analizVeSonuclartext") {
    textarea = document.getElementById(element);
    textarea.value =
      "Değerlemede Emsal Karşılaştırma Yöntemi kullanılmıştır. Emsallerin hepsi aynı bölgeden benzer özelliklerdeki taşınmazlardan seçilmiş olup, hâlihazırda birçok satılık taşınmazın bulunması, emsallerin pazarlıklı fiyatlar olması ve emsallerin irdelenmesi dikkate alınmıştır. Ayrıca taşınmazın bulunduğu konum, yaşı, cephesi, katı, ısıtma sistemi, kullanım alanı, fiziki durumu, manzara vb. özellikler göz önünde bulundurulmuştur. Bölgede satışta olan gayrimenkuller, bölge emlakçıları ile yapılan görüşmeler sonucunda taşınmazın değeri takdir edilmiştir.";
  } else if (element === "kanaatSatilabilirText") {
    textarea = document.getElementById(element);
    textarea.value =
      "Değerleme konusu taşınmaz, blok, kat ve kattaki konum olarak projesi ile uyumlu olması, aynı zamanda da tapu kayıtlarında satışa engel olabilecek herhangi bir kaydın da bulunmaması nedeniyle taşınmaz SATILABİLİR olarak nitelendirilmiştir.";
  } else if (element === "kanaatHisseliText") {
    textarea = document.getElementById(element);
    textarea.value =
      "Taşınmaz tapu kaydında hisseli olup değerleme tam hissesi için yapılmıştır. Tasarrufta bulunulması durumunda tüm maliklerin muvafakati gerekecektir.";
  } else if (element === "kanaatAlicisiAzText") {
    textarea = document.getElementById(element);
    textarea.value =
      "İlgili Belediyesinde yapılan incelemede konu taşınmazın konumlandığı ana taşınmaza ait dosyasında proje üzerinde numaralama yapılmamış olup dosyasında numarataj krokisi bulunmamaktadır. Tapu ve Kadastro Genel Müdürlüğünün projeleri taradığı dijital ortamda (Webtapu sisteminde), ana taşınmaza ait proje sistem arıza ve yoğunluğundan dolayı sistemden çekilememektedir. / yüklü değildir. Bu sebeplerden dolayı taşınmazın bağımsız bölüm bazında konum tespiti yapılamamış olup taşınmaz ALICISI AZ olarak nitelendirilmiştir.";
  } else if (element === "kanaatSatisiZorText") {
    textarea = document.getElementById(element);
    textarea.value = "...";
  } else if (element === "kanaatSatilamazText") {
    textarea = document.getElementById(element);
    textarea.value = "...";
  } else if (element === "kanaatInsSeviyeliText") {
    textarea = document.getElementById(element);
    textarea.value =
      "Konu taşınmaz halihazırda %85 inşaat seviyeli olup, herhangi bir nedenle inşaatın yasal prosedürlere uygun olarak tamamlanıp tamamlanamayacağı, Yapı ruhsatı süresinin yeterli olup olmayacağı, yenileme ruhsatı ve inşaatın tamamlanması durumunda iskan belgesinin alınıp alınamayacağı rapor tarihi itibari ile öngörülememekte olup, inşaatın herhangi bir nedenle tamamlanamama riski bulunmaktadır. İnşaatın yasal prosedürlere uygun olarak tamamlanması halindeki bitmiş durumu (%100 inşaat seviyesi) üzerinden değerleme yapılmış ve satış kabiliyeti SATILABİLİR olarak belirlenmiştir.";
  } else if (element === "degerTakdiriText") {
    textarea = document.getElementById(element);
    textarea.value =
      "Konu gayrimenkulün değerlemesinde emsal karşılaştırma yaklaşımı kullanılmıştır. Konumuz taşınmazın değerlendirmesinde civardaki alım satım rayiç değerleri ve günümüz ekonomik koşulları, taşınmazın konumu, yaşı, fiziki özellikleri, emsallerdeki pazarlık payları, arz/talep dengesi gibi dışsal etkenler dikkate alınmıştır.";
  }

  if (textarea) {
    adjustHeight(textarea); // Set height based on initial value
  }
};

function createCheckboxesLetter() {
  const container = document.getElementById('checkboxContainerLetter');
  const letters = 'ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ';

  letters.split('').forEach(letter => {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');

    checkbox.type = 'checkbox';
    checkbox.className = 'myCheckbox_atBloklar';
    checkbox.value = letter;
    checkbox.onchange = function () {
      updateSelecteddd(['atBloklar']);
    };

    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(letter));
    container.appendChild(label);
    // container.appendChild(document.createElement('br')); // Yeni satır
  });
};

function checkboxContainerNumber() {
  const container = document.getElementById('checkboxContainerNumber');
  const numbers = [...Array(29).keys()].map(n => n + 1); // 1'den 20'ye kadar sayılar

  numbers.forEach(number => {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');

    checkbox.type = 'checkbox';
    checkbox.className = 'myCheckbox_atBloklar';
    checkbox.value = number;
    checkbox.onchange = function () {
      updateSelecteddd(['atBloklar']);
    };

    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(number));
    container.appendChild(label);
    // container.appendChild(document.createElement('br')); // Yeni satır   
  });
};

function checkboxTakbisFarklilikSec() {
  const container = document.getElementById('checkboxTakbisFarklilikSec');
  let farkliliklar = ["ada numarası", "parsel numarası", "parsel yüzölçümü", "malik adı", "edinme sebebi", "edinme tarihi", "yevmiye numarası"];
  // let farkliliklar = farkliliklar_.sort((a, b) => a.localeCompare(b, 'tr'));

  farkliliklar.forEach(farklilik => {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');

    checkbox.type = 'checkbox';
    checkbox.className = 'myCheckbox_takbisFarklilikSec';
    checkbox.value = farklilik;
    checkbox.onchange = function () {
      updateSelectedFarklilik(['takbisFarklilikSec']);
    };

    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(farklilik));
    container.appendChild(label);
    // container.appendChild(document.createElement('br')); // Yeni satır   
  });
};

// Dropdown'u dinamik olarak doldurmak için bir fonksiyon
function populateDropdown(selectId, totalNumbers, defaultValue = null) {
  // Belirtilen ID ile select elemanını seç
  const selectElement = document.getElementById(selectId);

  // Select elemanını temizle (önceden eklenen seçenekler varsa)
  selectElement.innerHTML = '';

  // n'den totalNumbers'a kadar sayı aralığını oluştur ve seçenek ekle
  [...Array(totalNumbers).keys()].map(n => n + 0).forEach(value => {
    const option = document.createElement('option'); // Yeni option elementi oluştur
    option.value = value; // Value değeri olarak sayıyı ata
    option.textContent = value; // Görünecek metin olarak sayıyı ata
    if (value === defaultValue) { // Varsayılan seçim için kontrol
      option.selected = true;
    }
    selectElement.appendChild(option); // Option'ı select'e ekle
  });
};

function toggleInputs(checkboxId, inputIds, spanClass) {
  const checkbox = document.getElementById(checkboxId);
  const [adaInputId, parselInputId] = inputIds;

  const adaInput = document.getElementById(adaInputId);
  const parselInput = document.getElementById(parselInputId);

  if (checkbox.checked) {
    // Enable inputs
    adaInput.disabled = false;
    parselInput.disabled = false;

    // Update all span elements immediately with current values
    updateSpans(adaInputId, parselInputId, spanClass);
  } else {
    // Disable inputs and clear all span text
    adaInput.disabled = true;
    parselInput.disabled = true;
    clearSpans(spanClass);
  }
};

function updateSpans(adaInputId, parselInputId, spanClass) {
  const adaValue = document.getElementById(adaInputId).value.trim();
  const parselValue = document.getElementById(parselInputId).value.trim();

  // Find all spans with the given class
  const spanElements = document.querySelectorAll(`.${spanClass}`);

  spanElements.forEach(spanElement => {
    let description = "- Projenin, taşınmazın geçmişi olan ";

    if (adaValue && adaValue !== "0") {
      description += `${adaValue} ada `;
    }

    if (parselValue) {
      description += `${parselValue} parsel `;
    }

    description += "için hazırlanmış olduğu görülmüştür.";

    // Only update if ada or parsel value exists
    spanElement.textContent = adaValue || parselValue ? description : "";
  });
};

function clearSpans(spanClass) {
  // Clear all span elements with the given class
  const spanElements = document.querySelectorAll(`.${spanClass}`);
  spanElements.forEach(spanElement => {
    spanElement.textContent = "";
  });
};

function addDisableElement(elementId) {

  const element = document.getElementById(elementId);
  const checkbox = document.getElementById('atBloklarCheckbox');
  const selectedValueDivEle = document.getElementById('atBloklarDiv');
  const selectedValueEle = document.getElementById('selectedValue-atBloklar');
  const atBloklarManuelDivEle = document.getElementById('atBloklarManuelDiv');
  const atBloklarManuelEle = document.getElementById('atBloklarManuel');

  if (checkbox.checked) {
    element.classList.add("disabled");
    selectedValueDivEle.style.display = "none";
    atBloklarManuelDivEle.style.display = "block";
    document.querySelectorAll('.myCheckbox_atBloklar').forEach(checkbox => {
      checkbox.checked = false; // Her bir checkbox'un işaretini kaldır
    });
    selectedValueEle.innerText = "";
    atBloklarManuelEle.value = "";
    // var result = atBloklarManuelFunc()[0]
    // var resultLength = atBloklarManuelFunc()[1]
    // console.log("result_atBloklarManuelFunc:", result)
    // console.log("resultLength_atBloklarManuelFunc:", resultLength)

  } else {
    element.classList.remove("disabled");
    selectedValueDivEle.style.display = "block";
    atBloklarManuelDivEle.style.display = "none";
    // var result = updateSelecteddd(['atBloklar'])[0]
    // var resultLength = updateSelecteddd(['atBloklar'])[1]
    // console.log("result_updateSelecteddd:", result)
    // console.log("resultLength_updateSelecteddd:", resultLength)
  }
};

function atBloklarManuelFunc() {
  const atBloklarManuelEle = document.getElementById('atBloklarManuel');
  console.log("atBloklarManuelEle::::", atBloklarManuelEle)

  var result = atBloklarManuelEle.value
  var resultLength = (result.split(/[, -]+/).map(item => item.trim()).filter(Boolean)).length

  console.log("result::::", result)
  console.log("resultLength::::", resultLength)

  return [result, resultLength];
};

function bloklarFunc() {
  const checkbox = document.getElementById('atBloklarCheckbox');
  if (checkbox.checked) {
    var result = atBloklarManuelFunc()[0]
    var resultLength = atBloklarManuelFunc()[1]
    console.log("result_atBloklarManuelFunc:", result)
    console.log("resultLength_atBloklarManuelFunc:", resultLength)
  } else {
    var result = updateSelecteddd(['atBloklar'])[0]
    var resultLength = updateSelecteddd(['atBloklar'])[1]
    //console.log("result_updateSelecteddd:", result)
    //console.log("resultLength_updateSelecteddd:", resultLength)
  }

  return [result, resultLength];
};

function varyokBlok() {
  // 1 saniye (1000 ms) sonra çalışacak fonksiyon
  setTimeout(function () {
    //const pdfInputElement = document.getElementById('pdfInput');
    const varyokblok = document.getElementById('blok');
    const bloklarElement = document.getElementById('atBloklarID');
    const bbBlokElement = document.getElementById('bbBlokID');
    const anatasinmazgiriscephesiElement = document.getElementById('anatasinmazgiriscephesi');

    let meskenTekliElement = document.querySelectorAll('.mesken-tekli'); 
    let meskenBlokluElement = document.querySelectorAll('.mesken-bloklu'); 
    
   

    //console.log("varyokblok.value:", varyokblok.value)

    if (varyokblok.value === "") {
      // bbBlokElement.classList.add("disabled");
      bloklarElement.style.display = "none";
      bbBlokElement.style.display = "none";
      anatasinmazgiriscephesiElement.style.display = "block";
      meskenBlokluElement.forEach(element => {element.style.display = "none"});
      meskenTekliElement.forEach(element => {element.style.display = "block"});
    } else {
      // bbBlokElement.classList.remove("disabled");
      bloklarElement.style.display = "block";
      bbBlokElement.style.display = "block";
      anatasinmazgiriscephesiElement.style.display = "none";
      meskenBlokluElement.forEach(element => {element.style.display = "block"});
      meskenTekliElement.forEach(element => {element.style.display = "none"});
    }
    // pdfInputElement.value = '';
  }, 1000); // 1 saniye (1000 milisaniye) sonra çalışacak
};

function getDynamicValue(selectId) {
  // Select elementini al
  const selectElement = document.getElementById(selectId);

  // Eğer select bulunamazsa hata döndür
  if (!selectElement) {
    console.error(`Select element with ID "${selectId}" not found.`);
    return null;
  }

  // Select'ten seçili olan değeri al
  const selectedValue = selectElement.value;

  // Dinamik olarak hedef ID'yi oluştur
  const targetElementId = `${selectedValue}Text`;

  // Hedef elementin value değerini al
  const targetElement = document.getElementById(targetElementId);

  // Eğer hedef element bulunamazsa hata döndür
  if (!targetElement) {
    console.error(`Element with ID "${targetElementId}" not found.`);
    return null;
  }

  // Hedef elementin değerini döndür
  return targetElement.value;
};

function downloadDocx(textContainerr) {
  // Sayfanın karakter setini al
  const metaCharset = document.querySelector('meta[charset]');
  const charset = metaCharset ? metaCharset.getAttribute('charset') : 'UTF-8';
  // console.log("Karakter Seti:", charset);

  // textContainer öğesinin outerHTML'sini al
  var element = document.getElementById(textContainerr);
  var htmlContent = `
  <!DOCTYPE html>
  <html lang="tr">
  <head>
      <meta charset="UTF-8">
  </head>
  <body>
      ${element.outerHTML}
  </body>
  </html>
  `;

  // HTML içeriğini DOCX formatına dönüştür
  var converted = htmlDocx.asBlob(htmlContent);

  // DOCX dosyasını indirmek için bir bağlantı oluştur
  var link = document.createElement('a');
  link.href = URL.createObjectURL(converted);
  link.download = 'taslak.docx';
  link.click();
};

document.getElementById('pdfInput').addEventListener('change', function (event) {
  var file = event.target.files[0];
  if (file) {
    var formData = new FormData();
    formData.append("file", file); // Dosyayı FormData'ya ekle

    // Fetch ile dosyayı sunucuya gönder
    fetch('/takbisOku', {
      method: 'POST',
      body: formData  // FormData'yı doğrudan gönderiyoruz
    })
      .then(response => response.json())
      .then(data => {
        // console.log('Upload successful:', data);
        console.log(data.result);
        // Son satırı kaldırmak için
        const text = data.result
        const lines = text.split('\n');
        lines.pop(); // Son satırı kaldır
        const updatedText = lines.join('\n');
        console.log(updatedText);
        document.querySelectorAll(".yasalkisitlamalar").forEach((ele) => { ele.innerText = updatedText });
      })
      .catch(error => {
        console.error('Error during upload:', error);
      });
  }
});

// BLURRED NEW WINDOW
// // Get elements
// const openPopupBtn = document.getElementById('openPopupBtn');
// const closePopupBtn = document.getElementById('closePopupBtn');
// const popup = document.getElementById('popup');
// const blurBackground = document.getElementById('blurBackground');

// // Function to open the popup and blur background
// openPopupBtn.addEventListener('click', function () {
//     popup.style.display = 'block';  // Show the popup
//     blurBackground.classList.add('blurred-background');  // Apply the blur effect
// });

// // Function to close the popup and remove the blur effect
// closePopupBtn.addEventListener('click', function () {
//     popup.style.display = 'none';  // Hide the popup
//     blurBackground.classList.remove('blurred-background');  // Remove the blur effect
// });

// Get elements
const openPopupBtn = document.getElementById('openPopupBtn');
const closePopupBtn = document.getElementById('closePopupBtn');
const popup = document.getElementById('popup');
const body = document.body;

const ilTapuElement = document.getElementById('il');
const ilceTapuElement = document.getElementById('ilce');
const mahalleBelediyeElement = document.getElementById('belediyeMahalle');
const ilEmsalElement = document.getElementById('ilEmsal');
const ilceEmsalElement = document.getElementById('ilceEmsal');
const mahalleEmsalElement = document.getElementById('belediyeMahalleEmsal');

// Open popup and blur background
openPopupBtn.addEventListener('click', () => {
  console.log('Open button clicked'); // Kontrol için log
  ilEmsalElement.value = ilTapuElement.value
  ilceEmsalElement.value = ilceTapuElement.value
  mahalleEmsalElement.value = mahalleBelediyeElement.value
  console.log('ilTapuElement.value', ilTapuElement.value);
  console.log('ilceTapuElement.value', ilceTapuElement.value);
  console.log('mahalleBelediyeElement.value', mahalleBelediyeElement.value);
  if (popup && body) {
    popup.style.display = 'block';
    body.classList.add('blurred'); // Add blur to background
    console.log('Popup opened and background blurred'); // Kontrol için log
    console.log(body.className); // blurred içermeli
  } else {
    console.error('Popup or body not found'); // Hata mesajı
  }
});

// Close popup and remove blur
closePopupBtn.addEventListener('click', () => {
  console.log('Close button clicked'); // Kontrol için log
  if (popup && body) {
    popup.style.display = 'none';
    body.classList.remove('blurred'); // Remove blur from background
    console.log('Popup closed and background unblurred'); // Kontrol için log
  } else {
    console.error('Popup or body not found'); // Hata mesajı
  }
});

function kotSayisiKontrolu() {
  const kotAltiRuhsatElementValue = document.getElementById('kotAlti').value;
  const kotUstuRuhsatelementValue = document.getElementById('kotUstu').value;
  const kotAltiATElement = updateAllMenuText()[3]
  const kotUstuATElement = updateAllMenuText()[4]

  // console.log("kotAltiRuhsatElement:::", kotAltiRuhsatElementValue)
  // console.log("kotUstuRuhsatElement:::", kotUstuRuhsatelementValue)
  // console.log("kotAltiATElement:::", kotAltiATElement)
  // console.log("kotUstuATElement:::", kotUstuATElement)

  if (kotAltiRuhsatElementValue == kotAltiATElement && kotUstuRuhsatelementValue == kotUstuATElement) {
    kotSayisiText = `Ruhsattaki kot altı kat sayısı ${parseInt(kotAltiRuhsatElementValue)}, kot üstü kat sayısı ${parseInt(kotUstuRuhsatelementValue)}, toplam kat sayısı ${parseInt(kotAltiRuhsatElementValue) + parseInt(kotUstuRuhsatelementValue)} olup projesinde ve mahalde ruhsat ile uyumlu şeklindedir.`
  } else {
    kotSayisiText = `Ruhsattaki kot altı kat sayısı ${parseInt(kotAltiRuhsatElementValue)}, kot üstü kat sayısı ${parseInt(kotUstuRuhsatelementValue)}, toplam kat sayısı ${parseInt(kotAltiRuhsatElementValue) + parseInt(kotUstuRuhsatelementValue)}. Projesinde ve mahallinde kot altı kat sayısı ${kotAltiATElement}, kot üstü kat sayısı ${kotUstuATElement}, toplam kat sayısı ${kotAltiATElement + kotUstuATElement} olup ruhsat ile uyumlu değildir.`
  }
  return kotSayisiText;
};

function bbbolumleriEdit(id) {
  const bbbolumleri_1 = ["hol", "antre", "koridor", "mutfak", "salon", "salon+mutfak", "oda", "soyunma odası", "giyinme odası","kiler", "kış bahçesi", "zemin terası",];
  const bbbolumleri_2 = ["banyo/wc", "banyo", "wc", "lavabo", "ebeveyn banyo", "duş", "balkon", "kapalı balkon", "depo", "vestiyer", "teras"];

  const container = document.getElementById(id);

  function createCheckboxGroup(bbbolumleri) {
    const wrapperDiv = document.createElement("div");
    wrapperDiv.className = "col-50 container_checked2";

    bbbolumleri.forEach((bolum, index) => {
      const label = document.createElement("label");
      label.className = "container_checked container_checked3";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = bolum;
      checkbox.id = bolum;
      checkbox.name = id;
      if (index === 0) checkbox.checked = true;

      const span = document.createElement("span");
      span.className = "checkmark";

      const select = document.createElement("select");
      select.id = `${bolum}-select`;
      select.name = `${bolum}-select`;
      select.style.display = checkbox.checked ? "block" : "none";

      for (let i = 1; i <= 9; i++) {
        const option = document.createElement("option");
        option.value = i;
        option.textContent = i;
        select.appendChild(option);
      }

      checkbox.addEventListener("change", function () {
        select.style.display = this.checked ? "block" : "none";
      });

      label.appendChild(document.createTextNode(bolum.charAt(0).toUpperCase() + bolum.slice(1)));
      label.appendChild(checkbox);
      label.appendChild(span);
      label.appendChild(select);
      wrapperDiv.appendChild(label);
    });

    return wrapperDiv;
  }

  container.appendChild(createCheckboxGroup(bbbolumleri_1));
  container.appendChild(createCheckboxGroup(bbbolumleri_2));

  // Manuel giriş labeli
  const manuelLabel = document.createElement("label");
  manuelLabel.className = "container_checked_manuel";

  const manuelCheckbox = document.createElement("input");
  manuelCheckbox.type = "checkbox";
  manuelCheckbox.value = "";
  manuelCheckbox.id = `${id}-checkboxManuel`;
  manuelCheckbox.name = id;
  manuelCheckbox.style = "width: 25px; margin: 0;";

  const manuelText = document.createElement("input");
  manuelText.type = "text";
  manuelText.id = `${id}-checkboxManuel-text`;
  manuelText.placeholder = "...";
  manuelText.style = "opacity: 100; width:100px; border: 1px solid; outline: 1px solid; margin-left: 4px; margin-right: 4px;";

  const manuelSelect = document.createElement("select");
  manuelSelect.id = `${id}-checkboxManuel-select`;
  manuelSelect.style = "display:none; padding-top: 0px; padding-bottom: 0px;";

  for (let i = 1; i <= 9; i++) {
    const option = document.createElement("option");
    option.value = i;
    option.textContent = i;
    manuelSelect.appendChild(option);
  }

  manuelCheckbox.addEventListener("change", function () {
    manuelSelect.style.display = this.checked ? "block" : "none";
  });

  manuelLabel.appendChild(manuelCheckbox);
  manuelLabel.appendChild(manuelText);
  manuelLabel.appendChild(manuelSelect);
  container.appendChild(manuelLabel);
};

function bbAlanTurBolumlerEdit() {
  const select_dubleksmi = document.getElementById("dubleksmi");
  const bbalaniElement = document.getElementById("bbalani");

  const dubleksaltkatNoElement = document.getElementById("dubleksaltkatNo");
  const dubleksaltkatNameElement = document.getElementById("dubleksaltkatName");
  const dubleksaltkatAlaniElement = document.getElementById("dubleksaltkatAlani");

  const dubleksnormalkatNoElement = document.getElementById("dubleksnormalkatNo");
  const dubleksnormalkatNameElement = document.getElementById("dubleksnormalkatName");
  const dubleksnormalkatAlaniElement = document.getElementById("dubleksnormalkatAlani");

  const dubleksustkatNoElement = document.getElementById("dubleksustkatNo");
  const dubleksustkatNameElement = document.getElementById("dubleksustkatName");
  const dubleksustkatAlaniElement = document.getElementById("dubleksustkatAlani");

  // dubleks mi durumunu kontrol et 
  if (select_dubleksmi) {
    if (select_dubleksmi.value === "hayır") {
      var alanItem = bbalaniElement.value
      var bbItem = "taşınmazın"
      var bolumlerItem = processElements2("bbbolumleri")

    } else if (select_dubleksmi.value === "dubleks") {
      var alanItem = `${dubleksnormalkatNoElement.value}${dubleksnormalkatNameElement.value} ${dubleksnormalkatAlaniElement.value} m², ${dubleksustkatNoElement.value}${dubleksustkatNameElement.value} ${dubleksustkatAlaniElement.value} m² olmak üzere toplam ${parseFloat(dubleksnormalkatAlaniElement.value) + parseFloat(dubleksustkatAlaniElement.value)}`
      var bbItem = "dubleks meskenin"
      var bolumlerItem = `${dubleksnormalkatNoElement.value}${dubleksnormalkatNameElement.value}ta ${processElements2("bbbolumlerDubleksNormalKat")} bölümlerinden, ${dubleksustkatNoElement.value}${dubleksustkatNameElement.value}ta ${processElements2("bbbolumlerDubleksUstKat")}`

    } else if (select_dubleksmi.value === "tersdubleks") {
      var alanItem = `${dubleksaltkatNoElement.value}${dubleksaltkatNameElement.value} ${dubleksaltkatAlaniElement.value} m², ${dubleksnormalkatNoElement.value}${dubleksnormalkatNameElement.value} ${dubleksnormalkatAlaniElement.value} m² olmak üzere toplam ${parseFloat(dubleksaltkatAlaniElement.value) + parseFloat(dubleksnormalkatAlaniElement.value)}`
      var bbItem = "ters dubleks meskenin"
      var bolumlerItem = `${dubleksaltkatNoElement.value}${dubleksaltkatNameElement.value}ta ${processElements2("bbbolumlerDubleksAltKat")} bölümlerinden, ${dubleksnormalkatNoElement.value}${dubleksnormalkatNameElement.value}ta ${processElements2("bbbolumlerDubleksNormalKat")}`
    }
  }
  // console.log("bbAlani:::", alanItem)
  // console.log("bbTur:::", bbItem)
  // console.log("bolumlerItem:::", bolumlerItem)
  return [alanItem, bbItem, bolumlerItem];  
};

function koordinatlar() {
  const koordinatlarElementValue = document.getElementById('koordinatlar').value;

  let [enlemZiraat, boylamZiraat] = koordinatlarElementValue.split(" : ").map(value => value.replace(".", ","));
  let [enlemVakif, boylamVakif] = koordinatlarElementValue.split(" : ").map(value => value);
  
  return [enlemZiraat, boylamZiraat, enlemVakif, boylamVakif];
};


/* ************************************************************************************************ */
/* ************************************************************************************************ */

function updateData() {
  // Formdan veri çekme
  const formData = new FormData(document.getElementById("dataForm"));
  const data = Object.fromEntries(formData.entries());

  // Değişkenleri güncelleme 
  document.querySelectorAll(".varKotSayisi").forEach((ele) => { ele.textContent = kotSayisiKontrolu() });
  document.querySelectorAll(".varYasalKisitlamalar").forEach((ele) => { ele.textContent = document.getElementById('takbisFarklilikVarText').value });
  document.querySelectorAll(".varTarih").forEach((ele) => { ele.textContent = document.getElementById('tarih').value });
  document.querySelectorAll(".varil_").forEach((ele) => { ele.textContent = document.getElementById('il').value });
  document.querySelectorAll(".varilce_").forEach((ele) => { ele.textContent = document.getElementById('ilce').value });
  document.querySelectorAll(".varBelediyeMahalle").forEach((ele) => { ele.textContent = data.belediyeMahalle });
  document.querySelectorAll(".varBinaNo").forEach((ele) => { ele.textContent = data.binano });
  document.querySelectorAll(".varDaireNo").forEach((ele) => { ele.textContent = data.daireno });
  document.querySelectorAll(".varUavtNo").forEach((ele) => { ele.textContent = data.uavtno });
  document.querySelectorAll(".varPostaKodu").forEach((ele) => { ele.textContent = data.postaKodu });
  document.querySelectorAll(".varKoordinatEnlem").forEach((ele) => { ele.textContent = koordinatlar()[0] }); 
  document.querySelectorAll(".varKoordinatBoylam").forEach((ele) => { ele.textContent = koordinatlar()[1] });
  document.querySelectorAll(".varKoordinatEnlem2").forEach((ele) => { ele.textContent = koordinatlar()[2] }); 
  document.querySelectorAll(".varKoordinatBoylam2").forEach((ele) => { ele.textContent = koordinatlar()[3] });
  document.querySelectorAll(".varAnaArter").forEach((ele) => { ele.textContent = data.anaarter });
  document.querySelectorAll(".varYon").forEach((ele) => { ele.textContent = data.ulasimyon });
  document.querySelectorAll(".varUlasimYollari").forEach((ele) => { ele.textContent = processElements("ulasimyollariItem", "#ulasimyollaritext", "#ulasimyollariselect", ", ") });
  document.querySelectorAll(".varKullanimFonksiyon").forEach((ele) => { ele.textContent = data.kullanimfonksiyon });
  document.querySelectorAll(".varYapiKarakteriText").forEach((ele) => { ele.textContent = data.yapikarakteritext });
  document.querySelectorAll(".varYapiKarakteriSelect").forEach((ele) => { ele.textContent = data.yapikarakteriselect });
  document.querySelectorAll(".varGelirGrubu").forEach((ele) => { ele.textContent = data.gelirgrubu });
  document.querySelectorAll(".varYakinYer1").forEach((ele) => { ele.textContent = data.yakinyer1 });
  document.querySelectorAll(".varYakinYer2").forEach((ele) => { ele.textContent = data.yakinyer2 });
  document.querySelectorAll(".varAltYapi").forEach((ele) => { ele.textContent = processCheckboxesElements("altyapi") });
  document.querySelectorAll(".varUlasimTuru").forEach((ele) => { ele.textContent = data.ulasimturu });
  document.querySelectorAll(".varBolgeMerkezi").forEach((ele) => { ele.textContent = data.bolgekonumu });
  document.querySelectorAll(".varBolgeYapiYasi").forEach((ele) => { ele.textContent = data.bolgeyapiyasi });
  document.querySelectorAll(".varYapilasmaHizi").forEach((ele) => { ele.textContent = data.yapilasmahizi });
  document.querySelectorAll(".varTicariYogunluk").forEach((ele) => { ele.textContent = data.ticariyogunluk });
  document.querySelectorAll(".varYapiNizam").forEach((ele) => { ele.textContent = data.yapinizam });
  const isNotNumeric = !/^\d+$/.test(data.katno);
  const suffix = isNotNumeric ? "" : ". normal";
  document.querySelectorAll(".varKatNo").forEach((ele) => { ele.textContent = data.katno.toLowerCase() + suffix });
  document.querySelectorAll(".varSiteOzellikleri").forEach((ele) => { ele.textContent = processCheckboxesElements("siteozellik") });
  document.querySelectorAll(".varBloklar").forEach((ele) => { ele.textContent = bloklarFunc()[0] });
  document.querySelectorAll(".varBlokSayisi").forEach((ele) => { ele.textContent = sayiyiYaziyaCevir(bloklarFunc()[1]) });
  document.querySelectorAll(".varAnatasinmazNizam").forEach((ele) => { ele.textContent = data.anatasinmaznizam });
  document.querySelectorAll(".varBlok").forEach((ele) => { ele.textContent = data.bbBlok });
  document.querySelectorAll(".varbbBlokKonum").forEach((ele) => { ele.textContent = data.bbBlokKonumTextarea });
  document.querySelectorAll(".varInsaatTarzi").forEach((ele) => { ele.textContent = data.insaattarzi });
  document.querySelectorAll(".varYapiSinifi").forEach((ele) => { ele.textContent = data.yapisinifi });
  document.querySelectorAll(".varKatDuzeni").forEach((ele) => { ele.textContent = updateAllMenuText()[1] });
  document.querySelectorAll(".varAnatasinmazGirisYonu").forEach((ele) => { ele.textContent = data.anatasinmazgirisyonu });
  document.querySelectorAll(".varScbText").forEach((ele) => { ele.textContent = data.sokaktext });
  document.querySelectorAll(".varScbSelect").forEach((ele) => { ele.textContent = data.sokakselect });
  document.querySelectorAll(".varAnatasinmazGirisCephesi").forEach((ele) => { ele.textContent = data.anatasinmazgiriscephesi });
  document.querySelectorAll(".varAnatasinmazGirisSeviyesi").forEach((ele) => { ele.textContent = data.anatasinmazgirisseviyesi });
  document.querySelectorAll(".varKatIcerigi").forEach((ele) => { ele.textContent = updateAllMenuText()[0] });
  document.querySelectorAll(".varKatSayisi").forEach((ele) => { ele.textContent = updateAllMenuText()[2] });
  document.querySelectorAll(".varBBSayisiText").forEach((ele) => { ele.textContent = BBCount()[0] });
  document.querySelectorAll(".varBBSayisi").forEach((ele) => { ele.textContent = BBCount()[1] });
  document.querySelectorAll(".varBinaGirisKapisi").forEach((ele) => { ele.textContent = data.binagiriskapisi });
  document.querySelectorAll(".varInsaatAlani").forEach((ele) => { ele.textContent = data.insaatAlani });
  document.querySelectorAll(".varAntreZemini").forEach((ele) => { ele.textContent = data.antrezemini });
  document.querySelectorAll(".varAntreDuvari").forEach((ele) => { ele.textContent = data.antreduvari });
  document.querySelectorAll(".varBinaMerdiveni").forEach((ele) => { ele.textContent = data.binamerdiveni });
  document.querySelectorAll(".varKatSahanligi").forEach((ele) => { ele.textContent = data.katsahanligi });
  document.querySelectorAll(".varBinaKorkuluk").forEach((ele) => { ele.textContent = data.binakorkuluk });
  document.querySelectorAll(".varAsansor").forEach((ele) => { ele.textContent = data.asansor });
  document.querySelectorAll(".varDisCephe").forEach((ele) => { ele.textContent = data.discephe });
  document.querySelectorAll(".varOtopark1").forEach((ele) => { ele.textContent = data.otoparkselect });
  document.querySelectorAll(".varBinaIsinma").forEach((ele) => { ele.textContent = data.binaisinma });
  document.querySelectorAll(".varBinaBakimi").forEach((ele) => { ele.textContent = data.binabakimi });
  document.querySelectorAll(".varEKB").forEach((ele) => { ele.textContent = data.ekb });
  document.querySelectorAll(".varEKBNo").forEach((ele) => { ele.textContent = data.ekbText });

  // ***************** BB *****************************************************************************//
  document.querySelectorAll(".varbbno").forEach((ele) => { ele.textContent = document.getElementById('bbno_').value });
  document.querySelectorAll(".varbbDiger").forEach((ele) => { ele.textContent = bbKatKonumBirlestir() });
  document.querySelectorAll(".varBBtur").forEach((ele) => { ele.textContent = bbAlanTurBolumlerEdit()[1] });
  // document.querySelectorAll(".varBBalani").forEach((ele) => { ele.textContent = data.bbalani });
  document.querySelectorAll(".varBBalani").forEach((ele) => { ele.textContent = bbAlanTurBolumlerEdit()[0] });
  // document.querySelectorAll(".varBBbolumleri").forEach((ele) => { ele.textContent = processElements2("bbbolumleri") });
  document.querySelectorAll(".varBBbolumleri").forEach((ele) => { ele.textContent = bbAlanTurBolumlerEdit()[2] });
  document.querySelectorAll(".varBBZeminlerveDuvarlar").forEach((ele) => { ele.textContent = collectData() });
  document.querySelectorAll(".varBBbanyo").forEach((ele) => { ele.textContent = updateSelectedBanyo(["bbbanyo"])[0] });
  document.querySelectorAll(".varBBmutfakdolap").forEach((ele) => { ele.textContent = data.bbmutfakdolap });
  document.querySelectorAll(".varBBmutfaktezgah").forEach((ele) => { ele.textContent = data.bbmutfaktezgah });
  document.querySelectorAll(".varBBkapilaric").forEach((ele) => { ele.textContent = data.bbkapilaric });
  document.querySelectorAll(".varBBkapilardis").forEach((ele) => { ele.textContent = data.bbkapilardis });
  document.querySelectorAll(".varBBpencere").forEach((ele) => { ele.textContent = data.bbpencere });
  document.querySelectorAll(".varBBisinma").forEach((ele) => { ele.textContent = data.bbisinma });
  document.querySelectorAll(".varBBpetekkombiX").forEach((ele) => { ele.textContent = data.bbpetekkombi });
  document.querySelectorAll(".varBBeklentiSalonkartonpiyer").forEach((ele) => { ele.textContent = updateSelectedEklenti("bbeklenti")[0] });
  document.querySelectorAll(".varBBeklentiOdasalonkartonpiyer").forEach((ele) => { ele.textContent = updateSelectedEklenti("bbeklenti")[1] });
  document.querySelectorAll(".varBBeklentiDegerlemegunu").forEach((ele) => { ele.textContent = updateSelectedEklenti("bbeklenti")[2] });
  document.querySelectorAll(".varImarPlani").forEach((ele) => { ele.textContent = data.imarplani });
  document.querySelectorAll(".varPlanOlcek").forEach((ele) => { ele.textContent = data.planolcek });
  document.querySelectorAll(".varImarNizam").forEach((ele) => { ele.textContent = data.imarnizam });
  document.querySelectorAll(".varImarBirlestir").forEach((ele) => { ele.textContent = imarbirleştir()[0] });
  document.querySelectorAll(".varImarLejant").forEach((ele) => { ele.textContent = data.imarlejant });
  document.querySelectorAll(".varImarOzelDurum").forEach((ele) => { ele.textContent = data.imarOzelDurumtext });
  document.querySelectorAll(".varImarYolaterk").forEach((ele) => { ele.textContent = imarbirleştir()[1] });
  document.querySelectorAll(".varImareklentibelediyeicinde").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[0] });
  document.querySelectorAll(".varImareklentibelediyedisinda").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[1] });
  document.querySelectorAll(".varImareklentietkilememekte").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[2] });
  document.querySelectorAll(".varImareklentietkilemekte").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[3] });
  document.querySelectorAll(".varImareklentiresmibelgevar").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[4] });
  document.querySelectorAll(".varImareklentiresmibelgeyok").forEach((ele) => { ele.textContent = updateSelectedEklenti("imareklenti")[5] });
  document.querySelectorAll(".vardegerlemeTarihi").forEach((ele) => { ele.textContent = showDate1(data.degerlemeTarihi) });
  document.querySelectorAll(".varbelediyeTarihi").forEach((ele) => { ele.textContent = showDate2(data.belediyeTarihi) });
  document.querySelectorAll(".varProjeBilgileri").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[0] });
  document.querySelectorAll(".varRuhsatIskanBilgileri").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[1] });
  document.querySelectorAll(".varYapimYili").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[2] });
  document.querySelectorAll(".varProjeBilgileri2").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[3] });
  document.querySelectorAll(".varProjeBelediye").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[4] });
  document.querySelectorAll(".varRuhsatBilgileri").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[5] });
  document.querySelectorAll(".varIskanBilgileri").forEach((ele) => { ele.innerHTML = projeRuhsatIskanbirlestir()[6] });
  document.querySelectorAll(".varAdaParselKonumTespiti").forEach((ele) => { ele.textContent = data.adaParselKonutTespiti });
  document.querySelectorAll(".varblokKonumTespiti").forEach((ele) => { ele.textContent = binakonumbirlestir() });
  document.querySelectorAll(".varbbKonumTespiti").forEach((ele) => { ele.textContent = bbkonumbirlestir() });
  document.querySelectorAll(".varaykirilik").forEach((ele) => { ele.textContent = aykirilik() });
  document.querySelectorAll(".varolumsuzbelge").forEach((ele) => { ele.textContent = olumsuzBelge()[0] });
  document.querySelectorAll(".varolumsuzbelgeVakif").forEach((ele) => { ele.textContent = olumsuzBelge()[1] });
  document.querySelectorAll(".varyapidenetim").forEach((ele) => { ele.textContent = yapidenetim() });
  document.querySelectorAll(".varOtopark2").forEach((ele) => { ele.textContent = otopark() });
  document.querySelectorAll(".varGuvenlik").forEach((ele) => { ele.textContent = data.guvenlikselect });
  document.querySelectorAll(".varOlumluYonler").forEach((ele) => { ele.innerHTML = updateSelecteddd2(["bbolumlu"]) });
  document.querySelectorAll(".varOlumsuzYonler").forEach((ele) => { ele.innerHTML = updateSelecteddd2(["bbolumsuz"]) });
  document.querySelectorAll(".varAnalizVeSonuclarText").forEach((ele) => { ele.textContent = data.analizVeSonuclartext });
  document.querySelectorAll(".varSatisKanaati").forEach((ele) => { ele.textContent = getDynamicValue("satisKanaatiSelect") });
  document.querySelectorAll(".varDegerTakdiri").forEach((ele) => { ele.textContent = data.degerTakdiriText });

};

window.onload = function () {
  colorBox();
  setTodayDate();
  belediyeTarihiDuzenle();
  adjustHeightAutomatic("analizVeSonuclartext");
  adjustHeightAutomatic("kanaatSatilabilirText");
  adjustHeightAutomatic("kanaatHisseliText");
  adjustHeightAutomatic("kanaatAlicisiAzText");
  adjustHeightAutomatic("kanaatSatisiZorText");
  adjustHeightAutomatic("kanaatSatilamazText");
  adjustHeightAutomatic("kanaatInsSeviyeliText");
  adjustHeightAutomatic("degerTakdiriText");
  createCheckboxesLetter();
  checkboxContainerNumber();
  checkboxTakbisFarklilikSec()
  populateDropdown('kotAlti', 10, 0);
  populateDropdown('kotUstu', 100, 1);
  // deneme_10();
  // deneme_11();
  bbbolumleriEdit("bbbolumleri");
  bbbolumleriEdit("bbbolumlerDubleksAltKat");
  bbbolumleriEdit("bbbolumlerDubleksNormalKat");
  bbbolumleriEdit("bbbolumlerDubleksUstKat");
};

document.getElementById('AnalizEt').addEventListener('click', () => {
  // Kullanıcıdan alınan veriyi oku
  // const ilceData = document.getElementById('ilce').value;  
  // const mahalleData = document.getElementById('belediyeMahalle').value;
  const ilData = document.getElementById('ilEmsal').value || 'Bos Ilce';
  const ilceData = document.getElementById('ilceEmsal').value || 'Bos Ilce';
  console.log("ilceData:", ilceData)
  const mahalleData = document.getElementById('belediyeMahalleEmsal').value || 'Bos Mahalle';
  console.log("mahalleData:", mahalleData)

  // Fetch API ile veriyi Flask'a gönder
  fetch('/process', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ il: ilData, ilce: ilceData, mahalle: mahalleData }),
  })
    .then(response => response.json())
    .then(data => {
      // Flask'tan dönen sonucu ekrana yazdır
      console.log("Gelen Yanıt:", data);
      const resultText = document.getElementById('resultText');
      resultText.innerHTML = `İl: ${data.ilProcessed}, İlçe: ${data.ilceProcessed}, Mahalle: ${data.mahalleProcessed}<br><br> Oda+Salon Sayısı Bazında Analiz<br> ${data.grouped1Processed} <br> Bina Yaşı Bazında Analiz<br> ${data.grouped2Processed}<br> Emsaller ${data.dfEmsalProcessed}`;

      // Sayfadaki tüm tabloları seç
      let tables = document.querySelectorAll('table');

      // İlgili sütun adları
      const columnsToFormat = ["mean", "min", "max", "birimFiyat", "satisFiyati"];

      // Her bir tabloyu döngüyle gezip hücreleri kontrol et
      tables.forEach(table => {
        // Başlık satırını al
        const headers = table.querySelectorAll('thead th');

        // Başlıkları merkezle
        headers.forEach(header => {
          header.style.textAlign = 'center'; // Başlıkların hizalamasını merkezle
        });

        // Her bir satırı gez
        for (let row of table.rows) {
          // Eğer satırda başlıklar varsa (thead kullanılmışsa), başlık indekslerini al
          if (row.parentNode === table.tHead) {
            continue; // Başlık satırını atla, işlem sadece veri satırlarında yapılacak
          }

          for (let i = 0; i < row.cells.length; i++) {
            let cell = row.cells[i];
            let headerText = headers[i]?.innerText.trim().toLowerCase(); // Başlık metni

            // Eğer hücre başlıklarla eşleşiyorsa ve sayıya dönüştürülebilirse
            if (columnsToFormat.includes(headerText)) {
              // Hücredeki değeri sayıya çevir
              let value = parseFloat(cell.innerText.trim());
              if (!isNaN(value)) {
                // Binlik ayırıcı ile sayıyı formatla
                cell.innerText = value.toLocaleString('de-DE'); // Nokta ile ayır
              }
            }
          }
        }
      })

      /* *************************************************** */

      document.addEventListener('DOMContentLoaded', function () {
        // Kodunuzu buraya yazın
        const table = document.getElementById("dataTable");
        const tbody = table.querySelector("tbody");
        const columns = ["mean", "min", "max", "birimFiyat", "satisFiyati"];

        columns.forEach((column, index) => {
          const uniqueValues = getUniqueColumnValues(column);
          const selectElement = document.getElementById(`${column}Filter`);
          uniqueValues.forEach(value => {
            const option = document.createElement("option");
            option.value = value;
            option.textContent = value;
            selectElement.appendChild(option);
          });
        });

        columns.forEach((column) => {
          const selectElement = document.getElementById(`${column}Filter`);
          selectElement.addEventListener("change", () => {
            filterTable();
          });
        });

        function filterTable() {
          const filters = columns.reduce((acc, column) => {
            const selectElement = document.getElementById(`${column}Filter`);
            const value = selectElement.value;
            acc[column] = value ? value : null;
            return acc;
          }, {});

          Array.from(tbody.rows).forEach(row => {
            let showRow = true;
            columns.forEach((column, index) => {
              const cell = row.cells[index];
              const cellText = cell.textContent.trim();

              if (filters[column] && filters[column] !== cellText) {
                showRow = false;
              }
            });

            row.style.display = showRow ? "" : "none";
          });
        }

        function getUniqueColumnValues(column) {
          const columnIndex = columns.indexOf(column);
          const values = Array.from(tbody.rows).map(row => row.cells[columnIndex].textContent.trim());
          return [...new Set(values)];
        }
      });

    })
    .catch(error => {
      // Hata durumunda mesaj göster
      const resultText = document.getElementById('resultText');
      resultText.textContent = 'Bir hata oluştu!';
      console.error('Error:', error);
    });
});

// Tarayıcı Kapatma Algılama
window.addEventListener("beforeunload", function (event) {
  navigator.sendBeacon("/close_session");
});


// background: linear-gradient(to right, #4facfe, #00f2fe); 
// background: linear-gradient(to right,rgb(5,147,112),rgb(14,177,183));
// background: linear-gradient( #04AA6D, #45a049); 

// button: background: #007bff;
// button hover: background: #0056b3;













