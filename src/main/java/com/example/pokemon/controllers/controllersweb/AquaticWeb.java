package com.example.pokemon.controllers.controllersweb;


import com.example.pokemon.model.Aquatic;
import com.example.pokemon.services.AquaticServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/aquatics")
public class AquaticWeb {
    @Autowired // Inyección de Depencia
    private AquaticServices servicio;

    @RequestMapping("/tolistAquatic")
    public String tolistAquatic (Model model) {

        List<Aquatic> listAquatics = servicio.buscarTodo();
        System.out.println("List Aquatics: " + listAquatics);
        model.addAttribute("listAquatics", listAquatics);
        return "/modelAquatics/tolistAquatic";
    }

    @RequestMapping("/nuevo")
    public String newAquatic(Model model) {
        Aquatic aquatic = new Aquatic ();
        model.addAttribute("aquatic",aquatic);
        return "/modelAquatics/newAquatic";
    }


    @RequestMapping(value ="/guardar", method= RequestMethod.POST)
    public String createAquatic(@ModelAttribute("aquatic") Aquatic aquatic) {
        servicio.crear(aquatic);
        return "redirect:/aquatics/tolistAquatic";
    }


    @RequestMapping(value ="/actualizar/{id}")
    public ModelAndView editAquatic(@PathVariable(name="id") int id) {
        ModelAndView mav = new ModelAndView("/modelAquatics/editAquatic");
        Aquatic aquatic = servicio.buscarPorId(id);
        mav.addObject("aquatic",aquatic);
        return mav;
    }


    @RequestMapping(value = "/eliminar/{id}")
    public String deleteAquatic(@PathVariable(name="id") int id) {
        servicio.borrarPorId(id);
        return "redirect:/aquatics/tolistAquatic";
    }

}
