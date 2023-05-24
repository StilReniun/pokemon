package com.example.pokemon.controllers.controllersweb;

import com.example.pokemon.model.Fire;
import com.example.pokemon.services.FireServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/fires")
public class FireWeb {
    @Autowired // Inyección de Depencia
    private FireServices servicio;

    @RequestMapping("/tolistFire")
    public String tolistFire (Model model) {

        List<Fire> listFires = servicio.buscarTodo();
        System.out.println("List Fires: " + listFires);
        model.addAttribute("listFires", listFires);
        return "/modelFires/tolistFire";
    }

    @RequestMapping("/nuevo")
    public String newFire(Model model) {
        Fire fire = new Fire ();
        model.addAttribute("fire",fire);
        return "/modelFires/newFire";
    }


    @RequestMapping(value ="/guardar", method= RequestMethod.POST)
    public String createAquatic(@ModelAttribute("fire") Fire fire) {
        servicio.crear(fire);
        return "redirect:/fires/tolistFire";
    }


    @RequestMapping(value ="/actualizar/{id}")
    public ModelAndView editFire(@PathVariable(name="id") int id) {
        ModelAndView mav = new ModelAndView("/modelFires/editFire");
        Fire fire = servicio.buscarPorId(id);
        mav.addObject("fire",fire);
        return mav;
    }


    @RequestMapping(value = "/eliminar/{id}")
    public String deleteFire(@PathVariable(name="id") int id) {
        servicio.borrarPorId(id);
        return "redirect:/fires/tolistFire";
    }

}
