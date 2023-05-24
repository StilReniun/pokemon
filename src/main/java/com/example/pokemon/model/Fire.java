package com.example.pokemon.model;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name="fire")
@NamedQueries({
        @NamedQuery(name = "Fire.findAdll", query = "SELECT p FROM Aquatic p")
        ,@NamedQuery(name = "Fire.findByIdpokemon", query="SELECT p FROM Fire p WHERE p.idPokemon = :idPokemon")
        ,@NamedQuery(name = "Fire.findByNombre", query="SELECT p FROM Fire p WHERE p.nombre = :nombre")
        ,@NamedQuery(name = "Fire.findByImg", query="SELECT p FROM Fire p WHERE p.img = :img")
        ,@NamedQuery(name = "Fire.findByClase", query="SELECT p FROM Fire p WHERE p.clase = :clase")
        ,@NamedQuery(name = "Fire.findByRegion", query="SELECT p FROM Fire p WHERE p.region = :region")
        ,@NamedQuery(name = "Fire.findByCategoria", query="SELECT p FROM Fire p WHERE p.categoria = :categoria")
        ,@NamedQuery(name = "Fire.findByAtaque", query="SELECT p FROM Fire p WHERE p.ataque = :ataque")
        ,@NamedQuery(name = "Fire.findByVida", query="SELECT p FROM Fire p WHERE p.vida = :vida")

})
public class Fire implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false) //representa que este campo es obligatorio en base de datos
    @Column(name ="idPokemon")
    private Integer idPokemon;

    @Basic(optional = false)
    @Column(name ="nombre")
    private String nombre;

    @Column(name="img")
    private String img;

    @Column(name="clase")
    private String clase;

    @Column(name="region")
    private String region;

    @Column(name="categoria")
    private String categoria;

    @Column(name="ataque")
    private Integer ataque;
    @Column(name="vida")
    private Integer vida;

    public Fire(){

    }

    public Fire(Integer idPokemon, String nombre) {
        this.idPokemon = idPokemon;
        this.nombre = nombre;
    }

    public Fire(String nombre, String img, String clase, String region, String categoria, Integer ataque,
                   Integer vida) {
        super();
        this.nombre = nombre;
        this.img = img;
        this.clase = clase;
        this.region = region;
        this.categoria = categoria;
        this.ataque = ataque;
        this.vida = vida;
    }

    public Integer getIdPokemon() {
        return idPokemon;
    }

    public void setIdPokemon(Integer idPokemon) {
        this.idPokemon = idPokemon;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getImg() {
        return img;
    }

    public void setImg(String img) {
        this.img = img;
    }

    public String getClase() {
        return clase;
    }

    public void setClase(String clase) {
        this.clase = clase;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getCategoria() {
        return categoria;
    }

    public void setCategoria(String categoria) {
        this.categoria = categoria;
    }

    public Integer getAtaque() {
        return ataque;
    }

    public void setAtaque(Integer ataque) {
        this.ataque = ataque;
    }

    public Integer getVida() {
        return vida;
    }

    public void setVida(Integer vida) {
        this.vida = vida;
    }

    @Override
    public int hashCode() {
        return Objects.hash(idPokemon);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Fire other = (Fire) obj;
        return Objects.equals(idPokemon, other.idPokemon);
    }

    @Override
    public String toString() {
        return "Fire [idPokemon=" + idPokemon + "]";
    }

    public Fire buscarPorID(int i) {
        return null;
    }

    }


